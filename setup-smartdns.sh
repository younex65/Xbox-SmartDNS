#!/bin/bash
set -euo pipefail

INSTALL_DIR="/root/xbox-smartdns"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "=== Updating system ==="
apt-get update -y && apt-get upgrade -y

echo "=== Installing prerequisites ==="
apt-get install -y curl jq dnsutils python3 python3-pip cron ca-certificates iptables

# نصب Docker
if ! command -v docker &> /dev/null; then
    echo "=== Installing Docker ==="
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

# نصب Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "=== Installing Docker Compose ==="
    COMPOSE_VER=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r '.tag_name')
    curl -L "https://github.com/docker/compose/releases/download/$COMPOSE_VER/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

echo "=== Creating project files ==="

# ---------- config.env ----------
cat > config.env <<'EOF'
SMARTDNS_USER=admin
SMARTDNS_PASS=123456
EOF

# ---------- allowed_ips.txt ----------
touch allowed_ips.txt

# ---------- dnsmasq.conf.template ----------
cat > dnsmasq.conf.template <<'EOF'
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
EOF

# ---------- Dockerfile ----------
cat > Dockerfile <<'EOF'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq dnsutils python3 python3-pip python3-flask cron ca-certificates jq curl iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY dnsmasq.conf.template /app/dnsmasq.conf.template
COPY update-ips.sh /app/update-ips.sh
COPY apply-ips.sh /app/apply-ips.sh
COPY webview.py /app/webview.py
COPY config.env /app/config.env
COPY entrypoint.sh /app/entrypoint.sh
COPY allowed_ips.txt /app/allowed_ips.txt

RUN chmod +x /app/*.sh

RUN (crontab -l 2>/dev/null; echo "0 */12 * * * /app/update-ips.sh >> /var/log/xbox-smartdns-update.log 2>&1") | crontab -

EXPOSE 4000/tcp

ENTRYPOINT ["/app/entrypoint.sh"]
EOF

# ---------- entrypoint.sh ----------
cat > entrypoint.sh <<'EOF'
#!/bin/bash
set -euo pipefail

mkdir -p /var/log
touch /var/log/dnsmasq.log /var/log/xbox-smartdns-update.log

/app/update-ips.sh || true

service cron start
service dnsmasq start || true

python3 /app/webview.py &

tail -F /var/log/dnsmasq.log /var/log/xbox-smartdns-update.log
EOF
chmod +x entrypoint.sh

# ---------- update-ips.sh ----------
cat > update-ips.sh <<'EOF'
#!/bin/bash
set -euo pipefail
LOG_FILE="/var/log/xbox-smartdns-update.log"
DNSMASQ_CONF="/etc/dnsmasq.conf"
TEMPLATE="/app/dnsmasq.conf.template"

DOMAINS_AUTH=("xbox.com" "xboxlive.com" "login.live.com" "storeedgefd.dsx.mp.microsoft.com")
DOMAINS_CDN=("assets1.xboxlive.com" "assets2.xboxlive.com" "dlassets.xboxlive.com" "download.xbox.com")

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

get_country() {
    local ip=$1
    curl -s "https://ip-api.com/json/$ip?fields=countryCode" | jq -r '.countryCode'
}

resolve_best_ip() {
    local domain=$1 target_country=$2
    local ips=$(dig +short $domain | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    for ip in $ips; do
        [[ $(get_country $ip) == "$target_country" ]] && echo $ip && return
    done
    echo $(echo "$ips" | head -n1)
}

log "Starting hybrid update..."
echo "# Auto-generated DNSMasq config" > "$DNSMASQ_CONF"

for domain in "${DOMAINS_AUTH[@]}"; do
    ip=$(resolve_best_ip "$domain" "DE")
    [ -n "$ip" ] && log "Resolved $domain → $ip (DE)" && echo "address=/$domain/$ip" >> "$DNSMASQ_CONF"
done

for domain in "${DOMAINS_CDN[@]}"; do
    ip=$(resolve_best_ip "$domain" "NL")
    [ -n "$ip" ] && log "Resolved $domain → $ip (NL)" && echo "address=/$domain/$ip" >> "$DNSMASQ_CONF"
done

service dnsmasq restart
log "Update finished."
EOF
chmod +x update-ips.sh

# ---------- apply-ips.sh ----------
cat > apply-ips.sh <<'EOF'
#!/bin/bash
set -euo pipefail

ALLOWED_FILE="/app/allowed_ips.txt"
LOG_FILE="/var/log/xbox-smartdns-update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Applying DNS access rules ==="

# 🧹 Cleaning up the IP file (BOM, CRLF, spaces, duplicates, missing newline)
if [ -f "$ALLOWED_FILE" ]; then
    # Normalize line endings, remove BOM and trim spaces
    cat "$ALLOWED_FILE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'NF {gsub(/\xef\xbb\xbf/, ""); print $1}' | sort -u > /tmp/allowed_ips_clean.txt
    # Ensure there's always a trailing newline (bash read needs it)
    echo >> /tmp/allowed_ips_clean.txt
    mv /tmp/allowed_ips_clean.txt "$ALLOWED_FILE"
else
    log "[WARN] Allowed IPs file not found: $ALLOWED_FILE"
    exit 1
fi

# 🧱 Resetting old rules
iptables -D INPUT -p udp --dport 53 -j DNS_ALLOW 2>/dev/null || true
iptables -D INPUT -p tcp --dport 53 -j DNS_ALLOW 2>/dev/null || true
iptables -F DNS_ALLOW 2>/dev/null || true
iptables -X DNS_ALLOW 2>/dev/null || true

# 🧱 Create new chain
iptables -N DNS_ALLOW

# ✅ Add allowed IPs
while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    iptables -A DNS_ALLOW -s "$ip" -p udp --dport 53 -j ACCEPT
    iptables -A DNS_ALLOW -s "$ip" -p tcp --dport 53 -j ACCEPT
    log "[+] Allowed DNS access for $ip"
done < "$ALLOWED_FILE"

# 🔒 Default DROP for others
iptables -A DNS_ALLOW -p udp --dport 53 -j DROP
iptables -A DNS_ALLOW -p tcp --dport 53 -j DROP

# 🔗 Hook chain into INPUT
iptables -I INPUT -p udp --dport 53 -j DNS_ALLOW
iptables -I INPUT -p tcp --dport 53 -j DNS_ALLOW

log "[OK] DNS access rules applied successfully."

EOF
chmod +x apply-ips.sh

# ---------- webview.py ----------
cat > webview.py <<'EOF'
#!/usr/bin/env python3
# webview.py — updated with IP management modal and apply changes button
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify
import subprocess, functools, os, re, html, json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "xbox-smartdns-secret"

CONFIG_PATH = "/app/config.env"
LOG_FILE = "/var/log/xbox-smartdns-update.log"
ALLOWED_IPS_FILE = "/app/allowed_ips.txt"

# ---------- Utility ----------
def load_credentials():
    user, pwd = "admin", "123456"
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            for line in f:
                if line.startswith("SMARTDNS_USER="): user = line.strip().split("=",1)[1]
                elif line.startswith("SMARTDNS_PASS="): pwd = line.strip().split("=",1)[1]
    return user, pwd

def save_credentials(u, p):
    with open(CONFIG_PATH, "w") as f:
        f.write(f"SMARTDNS_USER={u}\nSMARTDNS_PASS={p}\n")

def load_ips():
    if not os.path.exists(ALLOWED_IPS_FILE): return []
    with open(ALLOWED_IPS_FILE) as f:
        return [x.strip() for x in f if x.strip()]

def save_ips(ips):
    with open(ALLOWED_IPS_FILE, "w") as f:
        f.write("\n".join(ips))

USER, PASS = load_credentials()
PASSWORD_HASH = generate_password_hash(PASS)

# ---------- Log utilities ----------
def read_logs(max_chars=12000):
    if not os.path.exists(LOG_FILE):
        return "No logs yet."
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()[-max_chars:]
    except Exception as e:
        return f"Error reading logs: {e}"

def escape_and_colorize(raw):
    text = html.escape(raw)
    # تاریخ و ساعت (سفید)
    text = re.sub(r'(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])',
                  r'<span style="color:#ffffff;font-weight:600;">\1</span>', text)
    # خطوط resolved (استخوانی)
    text = re.sub(r'(Resolved [^\n]+→ [0-9\.]+(?: \([A-Z]{2}\))?)',
                  r'<span style="color:#e8dcb8;">\1</span>', text)
    # IPها (سبز مدرن)
    text = re.sub(r'((?:\d{1,3}\.){3}\d{1,3})',
                  r'<span style="color:#aaffdd;font-weight:500;">\1</span>', text)
    # ERRORها با قرمز پررنگ
    text = re.sub(r'\b(ERROR|Failed)\b',
                  r'<span style="color:#ff6b6b;font-weight:bold;">\1</span>', text)
    return text.replace("\n", "<br>")

# ---------- Login system ----------
def login_required(f):
    @functools.wraps(f)
    def wrapper(*a, **k):
        if session.get("logged_in"): return f(*a, **k)
        return redirect(url_for("login"))
    return wrapper

@app.route("/login", methods=["GET","POST"])
def login():
    global USER, PASS, PASSWORD_HASH
    error=None
    if request.method=="POST":
        u=request.form.get("username","")
        p=request.form.get("password","")
        if u!=USER or not check_password_hash(PASSWORD_HASH,p):
            error="Invalid credentials"
        else:
            session["logged_in"]=True
            session["user"]=u
            return redirect(url_for("index"))
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Panel ----------
@app.route("/")
@login_required
def index():
    logs = escape_and_colorize(read_logs())
    ips = load_ips()
    return render_template_string(TEMPLATE, user=session.get("user"), logs=logs, ips=ips)

@app.route("/update", methods=["POST"])
@login_required
def update():
    subprocess.Popen(["/app/update-ips.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return redirect(url_for("index"))

@app.route("/apply-ips", methods=["POST"])
@login_required
def apply_ips():
    """
    Called when the user clicks 'Apply Changes' in the web UI.
    Runs the /app/apply-ips.sh script to apply DNS rules.
    """
    SCRIPT = "/app/apply-ips.sh"
    LOG_FILE = "/var/log/xbox-smartdns-update.log"

    if not os.path.exists(SCRIPT):
        return jsonify({"success": False, "error": f"Script not found: {SCRIPT}"}), 500

    try:
        res = subprocess.run(
            ["/bin/bash", SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=True
        )

        with open(LOG_FILE, "a") as lf:
            lf.write(f"[webview.py] apply script stdout:\n{res.stdout}\n")
            if res.stderr:
                lf.write(f"[webview.py] apply script stderr:\n{res.stderr}\n")

        return jsonify({"success": True, "message": res.stdout.strip()})

    except subprocess.CalledProcessError as e:
        err = e.stderr or str(e)
        with open(LOG_FILE, "a") as lf:
            lf.write(f"[webview.py] apply script failed: {err}\n")
        return jsonify({"success": False, "error": "Script failed", "details": err}), 500

    except subprocess.TimeoutExpired:
        with open(LOG_FILE, "a") as lf:
            lf.write("[webview.py] apply script timed out\n")
        return jsonify({"success": False, "error": "Script timed out"}), 500

    except Exception as e:
        with open(LOG_FILE, "a") as lf:
            lf.write(f"[webview.py] unexpected error: {e}\n")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    global USER, PASS, PASSWORD_HASH
    data = request.get_json() or {}
    new_user = (data.get("new_user") or "").strip()
    new_pass = data.get("new_pass") or ""
    if not new_user or not new_pass:
        return jsonify({"success": False, "error": "Username and password required"}), 400
    save_credentials(new_user, new_pass)
    USER, PASS = new_user, new_pass
    PASSWORD_HASH = generate_password_hash(PASS)
    session.clear()
    return jsonify({"success": True})

@app.route("/download-logs")
@login_required
def download_logs():
    if not os.path.exists(LOG_FILE): return "No logs", 404
    return (open(LOG_FILE,"rb").read(),200,{
        'Content-Type':'application/octet-stream',
        'Content-Disposition':'attachment; filename="xbox-smartdns-update.log"'})

# ---------- IP management API ----------
@app.route("/api/ips", methods=["GET","POST","DELETE"])
@login_required
def manage_ips():
    ips = load_ips()
    if request.method=="GET":
        return jsonify(ips)
    elif request.method=="POST":
        data = request.get_json() or {}
        new_ip = (data.get("ip") or "").strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", new_ip):
            return jsonify({"success":False,"error":"Invalid IP"}),400
        if new_ip not in ips:
            ips.append(new_ip)
            save_ips(ips)
        return jsonify({"success":True,"ips":ips})
    elif request.method=="DELETE":
        data = request.get_json() or {}
        rem_ip = data.get("ip")
        if rem_ip in ips:
            ips.remove(rem_ip)
            save_ips(ips)
        return jsonify({"success":True,"ips":ips})

# ---------- HTML templates ----------
# (از همان استایل دکمه‌های قبلی برای modal جدید استفاده شده)

TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>Xbox SmartDNS Panel</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>
:root{--bg:#0f1720;--accent:#00c8b8;--danger:#ff6b6b;--muted:#9aa4b2;--mono:ui-monospace,Menlo,Monaco;}
body{background:linear-gradient(180deg,#071021,var(--bg));color:#e6eef6;font-family:Inter,system-ui;}
.container{max-width:980px;margin:28px auto;padding:20px;background:rgba(255,255,255,0.02);border-radius:12px;}
.header{display:flex;justify-content:space-between;align-items:center;}
.btn{padding:10px 14px;border-radius:10px;border:none;cursor:pointer;font-weight:600;min-width:140px;}
.btn.primary,.btn.secondary{background:var(--accent);color:#012a2a;}
.btn.logout{background:var(--danger);color:#fff;}
.card{background:rgba(255,255,255,0.02);padding:14px;border-radius:10px;}
.logs{height:420px;overflow:auto;background:#02040a;border-radius:8px;padding:12px;font-family:var(--mono);font-size:13px;}
.modal-backdrop{position:fixed;inset:0;background:rgba(2,6,23,0.7);display:none;align-items:center;justify-content:center;}
.modal{background:#08121a;padding:18px;border-radius:12px;width:100%;max-width:420px;}
.input{width:100%;padding:10px;margin-bottom:8px;border-radius:8px;background:#041122;border:none;color:#d7eefb;}
.ip-list{background:#01080e;padding:8px;border-radius:8px;max-height:200px;overflow:auto;margin-top:8px;}
.ip-item{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.05);}
.remove-btn{background:none;border:none;color:var(--danger);cursor:pointer;}
</style></head><body>
<div class="container">
  <div class="header">
    <div><b>Xbox SmartDNS Panel</b><br><small>Logged in as {{ user }}</small></div>
    <div style="display:flex;gap:8px;">
      <button id="openIP" class="btn secondary">Manage Allowed IPs</button>
      <button id="openChange" class="btn secondary">Change Username / Password</button>
      <form method="post" action="/logout" style="display:inline;"><button class="btn logout" type="submit">Logout</button></form>
    </div>
  </div>
  <div style="margin-top:16px;">
    <form method="post" action="/update" style="display:inline;"><button class="btn primary" type="submit">Update IPs Now</button></form>
    <button id="applyIps" class="btn primary" style="margin-left:8px;">Apply Changes</button>
  </div>
  <div class="card" style="margin-top:16px;">
    <h3>Logs</h3>
    <div id="logs" class="logs">{{ logs|safe }}</div>
  </div>
</div>

<!-- Manage IP Modal -->
<div id="modalIpBk" class="modal-backdrop">
  <div class="modal">
    <h3>Manage Allowed IPs</h3>
	<button id="detectIpBtn" class="btn secondary" style="width:100%;margin-bottom:8px;">Detect My IP</button>
    <input id="new_ip" class="input" placeholder="Add new IP (e.g. 192.168.1.10)">
    <button id="addIpBtn" class="btn primary" style="width:100%;margin-bottom:8px;">Add IP</button>
    <div class="ip-list" id="ipList"></div>
    <div style="text-align:right;margin-top:8px;">
      <button id="closeIpModal" class="btn secondary">Close</button>
    </div>
  </div>
</div>

<!-- Change password modal (from previous version) -->
<div id="modalBk" class="modal-backdrop">
  <div class="modal">
    <h3>Change Credentials</h3>
    <input id="new_user" class="input" placeholder="New username">
    <input id="new_pass" class="input" type="password" placeholder="New password">
    <input id="new_pass_confirm" class="input" type="password" placeholder="Confirm new password">
    <div id="modalErr" style="color:var(--danger);"></div>
    <button id="modalSave" class="btn primary" style="width:100%;margin-top:8px;">Save</button>
    <button id="modalCancel" class="btn secondary" style="width:100%;margin-top:8px;">Cancel</button>
  </div>
</div>

<script>
/* ===== IP Modal ===== */
const ipModal = document.getElementById('modalIpBk'),
      openIP = document.getElementById('openIP'),
      closeIp = document.getElementById('closeIpModal'),
      ipList = document.getElementById('ipList'),
      addIp = document.getElementById('addIpBtn');

openIP.onclick = () => { ipModal.style.display = 'flex'; loadIPs(); };
closeIp.onclick = () => { ipModal.style.display = 'none'; };

function loadIPs() {
    fetch('/api/ips').then(r => r.json()).then(ips => {
        ipList.innerHTML = ips.length
            ? ips.map(ip => `<div class='ip-item'><span>${ip}</span>
                <button class='remove-btn' onclick="removeIP('${ip}')">🗑️</button></div>`).join('')
            : '<i>No IPs yet</i>';
    });
}

function removeIP(ip) {
    fetch('/api/ips', {
        method: 'DELETE',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ip})
    }).then(loadIPs);
}

addIp.onclick = () => {
    const ip = document.getElementById('new_ip').value.trim();
    if(!ip) return;
    fetch('/api/ips', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ip})
    }).then(()=> { document.getElementById('new_ip').value=''; loadIPs(); });
};

// Detect user's IP
document.getElementById('detectIpBtn').onclick = () => {
    fetch('https://api.ipify.org?format=json')
        .then(r => r.json())
        .then(d => { document.getElementById('new_ip').value = d.ip; })
        .catch(() => alert('Could not detect IP.'));
};

// Apply IP changes
document.getElementById('applyIps').onclick = () => {
    fetch('/apply-ips', {method:'POST'})
        .then(r => r.json())
        .then(res => alert(res.success ? 'Changes applied!' : 'Failed to apply changes'))
        .catch(() => alert('Error applying changes'));
};

/* ===== Change Credentials Modal ===== */
const changeModal = document.getElementById('modalBk'),
      openChange = document.getElementById('openChange'),
      modalSave = document.getElementById('modalSave'),
      modalCancel = document.getElementById('modalCancel'),
      modalErr = document.getElementById('modalErr');

openChange.onclick = () => { changeModal.style.display = 'flex'; modalErr.innerText = ''; };
modalCancel.onclick = () => { changeModal.style.display = 'none'; modalErr.innerText = ''; };

modalSave.onclick = () => {
    const new_user = document.getElementById('new_user').value.trim();
    const new_pass = document.getElementById('new_pass').value;
    const new_pass_confirm = document.getElementById('new_pass_confirm').value;

    if (!new_user || !new_pass) {
        modalErr.innerText = 'Username and password required';
        return;
    }
    if (new_pass !== new_pass_confirm) {
        modalErr.innerText = 'Passwords do not match';
        return;
    }

    fetch('/change-password', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({new_user, new_pass})
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            alert('Credentials updated. Logging out...');
            // POST request to logout and redirect to login
            fetch('/logout', { method: 'POST' })
                .finally(() => { window.location.href = '/login'; });
        } else {
            modalErr.innerText = res.error || 'Failed to change credentials';
        }
    })
    .catch(e => { modalErr.innerText = 'Error: ' + e; });
};
</script>
</body></html>"""

LOGIN_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>Login</title>
<style>body{background:#071021;color:#fff;font-family:Inter;display:flex;align-items:center;justify-content:center;height:100vh}
.box{background:#08121a;padding:28px;border-radius:12px;width:320px}
.input{width:100%;padding:10px;margin:6px 0;border:none;border-radius:8px;background:#041122;color:#fff}
.btn{width:100%;padding:10px;border:none;border-radius:8px;background:#00c8b8;color:#012a2a;font-weight:700}</style></head>
<body><div class="box"><h3>SmartDNS Login</h3>
<form method="post"><input name="username" class="input" placeholder="Username"><input type="password" name="password" class="input" placeholder="Password">
<button class="btn" type="submit">Login</button></form>{% if error %}<p style='color:red'>{{error}}</p>{% endif %}</div></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)

EOF

echo "=== Building Docker container ==="
docker build -t xbox-smartdns .

echo "=== Running Docker container ==="
docker run -d --name xbox-smartdns-hybrid --network host --cap-add=NET_ADMIN xbox-smartdns

echo "=== Setup complete ==="
echo "Web panel: http://<server-ip>:4000"
echo "Default login → Username: admin | Password: 123456"
