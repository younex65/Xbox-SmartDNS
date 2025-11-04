#!/bin/bash
set -euo pipefail

INSTALL_DIR="/root/dns"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "=== Updating system ==="
apt-get update -y && apt-get upgrade -y

echo "=== Installing prerequisites ==="
apt-get install -y curl jq dnsutils python3 python3-pip cron ca-certificates

# ensure dos2unix installed
if ! command -v dos2unix &> /dev/null; then
    echo "=== Installing dos2unix ==="
    apt-get install -y dos2unix
fi

# Install Docker if missing
if ! command -v docker &> /dev/null; then
    echo "=== Installing Docker ==="
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm -f get-docker.sh
fi

# Install docker-compose if missing
if ! command -v docker-compose &> /dev/null; then
    echo "=== Installing docker-compose ==="
    COMPOSE_VER=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r '.tag_name')
    curl -L "https://github.com/docker/compose/releases/download/$COMPOSE_VER/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

echo "=== Creating project files in $INSTALL_DIR ==="

# dnsmasq.conf.template
cat > dnsmasq.conf.template <<'DNSMASQ_EOF'
interface=eth0
listen-address=::1,127.0.0.1,0.0.0.0
no-hosts
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=10000
log-queries
log-facility=/var/log/dnsmasq.log
# Auto-generated mappings (do not edit)
# {{DOMAINS}}
DNSMASQ_EOF

# docker-compose.yml
cat > docker-compose.yml <<'COMPOSE_EOF'
version: '3.8'
services:
  xbox-smartdns:
    build: .
    container_name: xbox-smartdns-hybrid
    cap_add:
      - NET_ADMIN
    ports:
      - "53:53/udp"
      - "4000:4000/tcp"
    restart: unless-stopped
COMPOSE_EOF

# Dockerfile
cat > Dockerfile <<'DOCKER_EOF'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq dnsutils python3 python3-flask cron ca-certificates jq curl dos2unix && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY dnsmasq.conf.template /app/dnsmasq.conf.template
COPY update-ips.sh /app/update-ips.sh
COPY entrypoint.sh /app/entrypoint.sh
COPY webview.py /app/webview.py
RUN chmod +x /app/*.sh
# schedule update-ips to run every 12 hours inside container
RUN (crontab -l 2>/dev/null; echo "0 */12 * * * /app/update-ips.sh >> /var/log/xbox-smartdns-update.log 2>&1") | crontab -
EXPOSE 53/udp
EXPOSE 4000/tcp
ENTRYPOINT ["/app/entrypoint.sh"]
DOCKER_EOF

# entrypoint.sh
cat > entrypoint.sh <<'ENTRY_EOF'
#!/bin/bash
set -euo pipefail
mkdir -p /var/log /app
touch /var/log/dnsmasq.log /var/log/xbox-smartdns-update.log /app/allowed_ips.txt /app/config.env
# default creds if not present
if [ ! -s /app/config.env ]; then
  echo "USER=admin" > /app/config.env
  echo "PASS=123456" >> /app/config.env
fi
# initial update of xbox domains
/app/update-ips.sh || true
service cron start
service dnsmasq start || true
# start web panel in background
python3 /app/webview.py &
# keep container alive by tailing logs
tail -F /var/log/dnsmasq.log /var/log/xbox-smartdns-update.log
ENTRY_EOF
chmod +x entrypoint.sh

# update-ips.sh (updates xbox domains and restarts dnsmasq)
cat > update-ips.sh <<'UPDATE_EOF'
#!/bin/bash
set -euo pipefail
LOG_FILE="/var/log/xbox-smartdns-update.log"
DNSMASQ_CONF="/etc/dnsmasq.conf"
TEMPLATE="/app/dnsmasq.conf.template"

DOMAINS_AUTH=("xbox.com" "xboxlive.com" "login.live.com" "storeedgefd.dsx.mp.microsoft.com")
DOMAINS_CDN=("assets1.xboxlive.com" "assets2.xboxlive.com" "dlassets.xboxlive.com" "download.xbox.com")

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

get_country() {
    local ip="$1"
    curl -s "https://ip-api.com/json/$ip?fields=countryCode" | jq -r '.countryCode'
}

resolve_best_ip() {
    local domain="$1" target_country="$2"
    local ips
    ips=$(dig +short "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' || true)
    local best=""
    for ip in $ips; do
        country=$(get_country "$ip")
        if [ "$country" = "$target_country" ]; then
            best="$ip"
            break
        fi
    done
    if [ -z "$best" ]; then
        best=$(echo "$ips" | head -n1)
    fi
    echo "$best"
}

log "Starting Xbox domain update..."
if [ -f "$TEMPLATE" ]; then
    cp "$TEMPLATE" "$DNSMASQ_CONF"
else
    echo "# Auto-generated" > "$DNSMASQ_CONF"
fi

for domain in "${DOMAINS_AUTH[@]}"; do
    ip=$(resolve_best_ip "$domain" "DE")
    if [ -n "$ip" ]; then
        log "Resolved $domain → $ip (DE)"
        echo "address=/$domain/$ip" >> "$DNSMASQ_CONF"
    fi
done

for domain in "${DOMAINS_CDN[@]}"; do
    ip=$(resolve_best_ip "$domain" "NL")
    if [ -n "$ip" ]; then
        log "Resolved $domain → $ip (NL)"
        echo "address=/$domain/$ip" >> "$DNSMASQ_CONF"
    fi
done

service dnsmasq restart || true
log "Xbox domain update finished."
UPDATE_EOF
chmod +x update-ips.sh

# webview.py (final with modal UI, AJAX endpoints, confirm-password, logs textarea)
cat > webview.py <<'WEBVIEW_EOF'
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify
import subprocess, functools, os, time
from werkzeug.security import generate_password_hash, check_password_hash

CONFIG_PATH = "/app/config.env"
ALLOW_PATH = "/app/allowed_ips.txt"
LOG_PATH = "/var/log/xbox-smartdns-update.log"

app = Flask(__name__)
app.secret_key = "xbox-smartdns-secret"

def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            f.write("USER=admin\nPASS=123456\n")
    lines = [l.strip() for l in open(CONFIG_PATH).read().splitlines() if l.strip() and "=" in l]
    conf = dict(line.split("=",1) for line in lines)
    return conf.get("USER","admin"), conf.get("PASS","123456")

# initial credentials loaded from file
USER, PASS = load_config()
PASSWORD_HASH = generate_password_hash(PASS)

def save_config(user, pw):
    with open(CONFIG_PATH, "w") as f:
        f.write(f"USER={user}\nPASS={pw}\n")

def login_required(f):
    @functools.wraps(f)
    def wrapper(*a, **k):
        if session.get("logged_in"):
            return f(*a, **k)
        return redirect(url_for("login"))
    return wrapper

@app.route("/login", methods=["GET","POST"])
def login():
    global USER, PASSWORD_HASH
    error = None
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "").strip()
        if not u or not p:
            error = "Invalid credentials"
        else:
            if u == USER and check_password_hash(PASSWORD_HASH, p):
                session["logged_in"] = True
                session["user"] = u
                return redirect(url_for("index"))
            else:
                error = "Invalid credentials"
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/", methods=["GET"])
@login_required
def index():
    logs = "No logs yet."
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                logs = f.read()[-8000:]
        except Exception:
            logs = "Could not read logs."
    # read current allowlist for initial render (not shown here, fetched via AJAX)
    return render_template_string(MAIN_TEMPLATE, user=session.get("user"), logs=logs)

@app.route("/update", methods=["POST"])
@login_required
def update():
    subprocess.Popen(["/app/update-ips.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    return redirect(url_for("index"))

# AJAX endpoint to change credentials
@app.route("/api/change_credentials", methods=["POST"])
@login_required
def api_change_credentials():
    global USER, PASSWORD_HASH, PASS
    data = request.get_json() or {}
    new_user = (data.get("new_user") or "").strip()
    new_pass = (data.get("new_pass") or "").strip()
    confirm_pass = (data.get("confirm_pass") or "").strip()
    if not new_user or not new_pass:
        return jsonify({"ok": False, "error": "Username and password cannot be empty."}), 400
    if new_pass != confirm_pass:
        return jsonify({"ok": False, "error": "Passwords do not match."}), 400
    # save
    save_config(new_user, new_pass)
    USER = new_user
    PASS = new_pass
    PASSWORD_HASH = generate_password_hash(new_pass)
    # clear session so client must re-login
    session.clear()
    return jsonify({"ok": True})

# AJAX endpoints for allowlist
@app.route("/api/allowlist", methods=["GET"])
@login_required
def api_allowlist_get():
    ips = []
    if os.path.exists(ALLOW_PATH):
        ips = [l.strip() for l in open(ALLOW_PATH).read().splitlines() if l.strip()]
    return jsonify({"ok": True, "ips": ips})

@app.route("/api/allowlist", methods=["POST"])
@login_required
def api_allowlist_add():
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "Empty IP"}), 400
    existing = []
    if os.path.exists(ALLOW_PATH):
        existing = [l.strip() for l in open(ALLOW_PATH).read().splitlines() if l.strip()]
    if ip in existing:
        return jsonify({"ok": False, "error": "Already exists"}), 400
    with open(ALLOW_PATH, "a") as f:
        f.write(ip + "\n")
    # trigger update-ips.sh to reapply rules (optional)
    subprocess.Popen(["/app/update-ips.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return jsonify({"ok": True, "ip": ip})

@app.route("/api/allowlist/remove", methods=["POST"])
@login_required
def api_allowlist_remove():
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "Empty IP"}), 400
    if os.path.exists(ALLOW_PATH):
        lines = [l.strip() for l in open(ALLOW_PATH).read().splitlines() if l.strip() and l.strip() != ip]
        with open(ALLOW_PATH, "w") as f:
            if lines:
                f.write("\n".join(lines) + "\n")
            else:
                f.write("")
        subprocess.Popen(["/app/update-ips.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return jsonify({"ok": True, "ip": ip})

# Serve logs periodically via AJAX
@app.route("/api/logs", methods=["GET"])
@login_required
def api_logs():
    logs = "No logs yet."
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                logs = f.read()[-8000:]
        except Exception:
            logs = "Could not read logs."
    return jsonify({"ok": True, "logs": logs})

# --- Templates (MAIN_TEMPLATE contains JS for modals & AJAX) ---
LOGIN_TEMPLATE = """<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Login</title>
<style>
body{background:#0f1720;color:#e6eef3;text-align:center;font-family:Inter,system-ui,Segoe UI,Roboto,Arial;}
.login-box{background:linear-gradient(180deg,#0b1220,#121826);border:1px solid rgba(255,255,255,0.03);border-radius:10px;padding:34px;margin:80px auto;width:360px;box-shadow:0 8px 30px rgba(2,6,23,0.6);}
input{width:92%;padding:12px;margin:10px 0;border-radius:8px;border:1px solid rgba(255,255,255,0.06);background:#07101a;color:#dff7ef;}
button{background:#00e0a8;border:none;color:#04211a;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:600;}
button:hover{filter:brightness(1.05);}
h2{margin-bottom:6px;color:#c7fff0;}
.error{color:#ff7b7b;margin-top:8px}
</style></head><body><div class='login-box'>
<h2>SmartDNS Login</h2><form method='post'>
<input name='username' placeholder='Username' required><br>
<input name='password' type='password' placeholder='Password' required><br>
<button type='submit'>Login</button></form>{% if error %}<div class='error'>{{ error }}</div>{% endif %}
</div></body></html>"""

MAIN_TEMPLATE = """<!DOCTYPE html><html lang='en'><head>
<meta charset='UTF-8'><title>Xbox SmartDNS Panel</title>
<style>
/* overall */
body{background:#0f1720;color:#e6eef3;font-family:Inter,system-ui,Segoe UI,Roboto,Arial;text-align:center;}
.container{max-width:980px;margin:30px auto;padding:22px;background:linear-gradient(180deg,#08131a,#0e1a20);border-radius:12px;border:1px solid rgba(255,255,255,0.03);box-shadow:0 10px 40px rgba(2,6,23,0.6);}
/* header */
.header-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}
.header-row .user{color:#bfffe9;font-weight:600;}
.controls{display:flex;gap:10px;flex-wrap:wrap;}
.btn{background:#00e0a8;border:none;color:#04211a;padding:10px 18px;border-radius:8px;cursor:pointer;font-weight:600;}
.btn:hover{filter:brightness(1.05);}
.btn-danger{background:#ff6b6b;color:white;}
/* textarea */
textarea{width:100%;height:360px;background:#001216;color:#9efae0;font-family:Menlo,monospace;font-size:13px;border-radius:8px;padding:12px;border:1px solid rgba(255,255,255,0.02);white-space:pre-wrap;overflow:auto;}
/* modal backdrop */
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:none;align-items:center;justify-content:center;z-index:1000;}
.modal{width:520px;background:linear-gradient(180deg,#08131a,#0e1a20);border-radius:12px;padding:20px;border:1px solid rgba(255,255,255,0.03);box-shadow:0 10px 30px rgba(2,6,23,0.6);color:#e6eef3;}
.modal h3{margin-top:0;color:#c7fff0;}
.input{width:92%;padding:10px;margin:8px 0;border-radius:8px;border:1px solid rgba(255,255,255,0.06);background:#07101a;color:#dff7ef;}
.small{font-size:13px;color:#9efad8;margin-top:6px;}
.table{width:100%;border-collapse:collapse;margin-top:12px;}
.table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.02);text-align:left;}
.close-x{float:right;background:transparent;border:none;color:#9efad8;font-weight:700;font-size:18px;cursor:pointer;}
</style>
</head>
<body>
<div class='container'>
  <div class='header-row'>
    <div>
      <h2 style='margin:0;color:#dfffe8'>Xbox SmartDNS Panel</h2>
      <div class='user'>Logged in as: {{ user }}</div>
    </div>
    <div class='controls'>
      <button class='btn' id='btn-update'>Update Xbox IPs Now</button>
      <button class='btn' id='btn-change'>Change Username/Password</button>
      <button class='btn' id='btn-allow'>Manage Allowed IPs</button>
      <form method='post' action='/logout' style='display:inline;'><button class='btn btn-danger' type='submit'>Logout</button></form>
    </div>
  </div>

  <h3 style='text-align:left;color:#bfffe9'>Latest Logs</h3>
  <textarea id='logs' readonly>{{ logs }}</textarea>
</div>

<!-- Modal: Change credentials -->
<div class='modal-backdrop' id='modal-cred'>
  <div class='modal' role='dialog' aria-modal='true'>
    <button class='close-x' id='close-cred' title='Close'>×</button>
    <h3>Change Username / Password</h3>
    <div class='small'>After changing credentials you will be logged out and must log in with the new credentials.</div>
    <div style='margin-top:12px;'>
      <input id='new_user' class='input' placeholder='New Username' />
      <input id='new_pass' class='input' type='password' placeholder='New Password' />
      <input id='confirm_pass' class='input' type='password' placeholder='Confirm New Password' />
      <div id='cred-msg' class='small' style='color:#ff7b7b;display:none;'></div>
      <div style='margin-top:12px;display:flex;gap:8px;justify-content:flex-end;'>
        <button class='btn' id='cred-save'>Save</button>
        <button class='btn' id='cred-cancel'>Cancel</button>
      </div>
    </div>
  </div>
</div>

<!-- Modal: Allowlist -->
<div class='modal-backdrop' id='modal-allow'>
  <div class='modal' role='dialog' aria-modal='true'>
    <button class='close-x' id='close-allow' title='Close'>×</button>
    <h3>Allowed IPs</h3>
    <div class='small'>Only IPs listed here can use the DNS. (Empty list → no one allowed)</div>
    <div style='margin-top:12px;display:flex;gap:8px;align-items:center;'>
      <input id='add_ip' class='input' placeholder='Add new IP (e.g. 1.2.3.4)' />
      <button class='btn' id='add-ip-btn'>Add</button>
    </div>
    <table class='table' id='allow-table'>
      <tr><th>IP Address</th><th></th></tr>
    </table>
    <div id='allow-msg' class='small' style='color:#9efad8;display:none;margin-top:10px;'></div>
    <div style='margin-top:12px;display:flex;justify-content:flex-end;'>
      <button class='btn' id='allow-close'>Close</button>
    </div>
  </div>
</div>

<script>
// helper
function qs(id){return document.getElementById(id);}
function showModal(m){qs(m).style.display='flex';}
function hideModal(m){qs(m).style.display='none';}

// open modals
qs('btn-change').addEventListener('click', ()=>{ showModal('modal-cred'); qs('cred-msg').style.display='none'; });
qs('btn-allow').addEventListener('click', ()=>{ showModal('modal-allow'); loadAllowlist(); });

// close handlers
['close-cred','cred-cancel'].forEach(id=>qs(id).addEventListener('click', ()=>hideModal('modal-cred')));
['close-allow','allow-close'].forEach(id=>qs(id).addEventListener('click', ()=>hideModal('modal-allow')));

// Update Xbox IPs button (form submit to /update)
qs('btn-update').addEventListener('click', ()=>{
  // use fetch POST to /update (which expects form POST)
  fetch('/update', {method:'POST'}).then(r=>{ // refresh logs after a short delay
    setTimeout(()=> fetchLogs(), 1500);
  });
});

// Credential save (AJAX)
qs('cred-save').addEventListener('click', async ()=>{
  const new_user = qs('new_user').value.trim();
  const new_pass = qs('new_pass').value;
  const confirm_pass = qs('confirm_pass').value;
  const msg = qs('cred-msg');
  msg.style.display='none';
  if(!new_user || !new_pass){ msg.textContent='Username and password cannot be empty.'; msg.style.display='block'; return; }
  if(new_pass !== confirm_pass){ msg.textContent='Passwords do not match.'; msg.style.display='block'; return; }
  try{
    const res = await fetch('/api/change_credentials', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({new_user, new_pass, confirm_pass})
    });
    const j = await res.json();
    if(res.ok && j.ok){
      // successful: close modal, show message then redirect to login
      hideModal('modal-cred');
      alert('Credentials changed — you will be logged out. Please log in with new credentials.');
      window.location = '/login';
    } else {
      msg.textContent = j.error || 'Failed';
      msg.style.display='block';
    }
  }catch(e){
    msg.textContent='Network error';
    msg.style.display='block';
  }
});

// Allowlist: load and render
async function loadAllowlist(){
  qs('allow-msg').style.display='none';
  const t = qs('allow-table');
  // clear rows except header
  t.innerHTML = "<tr><th>IP Address</th><th></th></tr>";
  try{
    const res = await fetch('/api/allowlist');
    const j = await res.json();
    if(j.ok){
      for(const ip of j.ips){
        const tr = document.createElement('tr');
        const td1 = document.createElement('td'); td1.textContent = ip;
        const td2 = document.createElement('td');
        const f = document.createElement('form'); f.style.display='inline';
        f.innerHTML = "<input type='hidden' name='ip' value='"+ip+"'><button class='remove' data-ip='"+ip+"'>Remove</button>";
        td2.appendChild(f);
        tr.appendChild(td1); tr.appendChild(td2);
        t.appendChild(tr);
      }
      // attach remove handlers
      t.querySelectorAll('button.remove').forEach(btn=>{
        btn.addEventListener('click', async (ev)=>{
          ev.preventDefault();
          const ip = btn.getAttribute('data-ip');
          try{
            const res = await fetch('/api/allowlist/remove', {
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body: JSON.stringify({ip})
            });
            const j = await res.json();
            if(res.ok && j.ok){
              qs('allow-msg').textContent = 'Removed ' + ip;
              qs('allow-msg').style.display = 'block';
              loadAllowlist();
            } else {
              qs('allow-msg').textContent = j.error || 'Remove failed';
              qs('allow-msg').style.display = 'block';
            }
          }catch(e){
            qs('allow-msg').textContent='Network error';
            qs('allow-msg').style.display='block';
          }
        });
      });
    }
  }catch(e){
    qs('allow-msg').textContent='Could not load list';
    qs('allow-msg').style.display='block';
  }
}

// Add IP
qs('add-ip-btn').addEventListener('click', async (ev)=>{
  ev.preventDefault();
  const ip = qs('add_ip').value.trim();
  if(!ip){ qs('allow-msg').textContent='Enter an IP'; qs('allow-msg').style.display='block'; return; }
  try{
    const res = await fetch('/api/allowlist', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip})
    });
    const j = await res.json();
    if(res.ok && j.ok){
      qs('allow-msg').textContent = 'Added ' + ip;
      qs('allow-msg').style.display='block';
      qs('add_ip').value='';
      loadAllowlist();
    } else {
      qs('allow-msg').textContent = j.error || 'Add failed';
      qs('allow-msg').style.display='block';
    }
  }catch(e){
    qs('allow-msg').textContent='Network error';
    qs('allow-msg').style.display='block';
  }
});

// Logs: fetch periodically
async function fetchLogs(){
  try{
    const res = await fetch('/api/logs');
    const j = await res.json();
    if(j.ok){
      qs('logs').textContent = j.logs;
    }
  }catch(e){}
}
setInterval(fetchLogs, 3000);
</script>
</body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)
WEBVIEW_EOF

# ensure unix line endings
dos2unix dnsmasq.conf.template docker-compose.yml Dockerfile entrypoint.sh update-ips.sh webview.py >/dev/null 2>&1 || true

echo "=== Building Docker image (may take a minute) ==="
docker-compose build --no-cache

echo "=== Starting container ==="
docker-compose up -d

echo "=== Quick DNS test inside container (may fail until allowlist set) ==="
sleep 4
dig_result=$(docker exec xbox-smartdns-hybrid dig +short xbox.com || echo "Failed")
echo "DNS test result for xbox.com: $dig_result"

echo "=== Deployment finished ==="
echo "Web panel: http://<server-ip>:4000 (default user: admin / pass: 123456)"
