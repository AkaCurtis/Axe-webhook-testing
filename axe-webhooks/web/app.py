import os
import json
import requests
import socket
import subprocess
import base64
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, jsonify

app = Flask(__name__)

CONFIG_PATH = "/data/config.json"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()

# Hardcoded JWT secret for proxy token generation (fallback if JWT_SECRET env var not set)
DEFAULT_JWT_SECRET = "fd820bbcbbc6cc59a0ce68a8b4914b3763bba0da557ba30dc9c884d4b4a2a0b9"

# JWT Token Generation Helper
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def generate_umbrel_proxy_token(jwt_secret: str, years: int = 10) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    exp = int((datetime.now(timezone.utc) + timedelta(days=365 * years)).timestamp())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"proxyToken": True, "iat": now, "exp": exp}

    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
        b64url(json.dumps(payload, separators=(",", ":")).encode())
    )

    sig = hmac.new(jwt_secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def get_host_ip():
    """Get the Docker host IP (gateway) where Umbrel is running"""
    try:
        # Try to get default gateway (Docker host)
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            # Parse output like: "default via 172.17.0.1 dev eth0"
            parts = result.stdout.split()
            if "via" in parts:
                gateway_ip = parts[parts.index("via") + 1]
                return gateway_ip
    except Exception:
        pass
    
    # Fallback: try to detect by connecting to external host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            # Gateway is typically .1 in the same subnet
            parts = local_ip.split(".")
            parts[-1] = "1"
            return ".".join(parts)
    except Exception:
        pass
    
    return "192.168.1.1"  # Final fallback

def load_config():
    host_ip = get_host_ip()
    defaults = {
        "base_url": f"http://{host_ip}",
        "bch_port": "21212",
        "xec_port": "21218",
        "btc_port": "21215",
        "dbg_port": "21213",
        "bc2_path": "",
        "bch2_path": "",
        "bch_base": f"http://{host_ip}:21212",
        "xec_base": f"http://{host_ip}:21218",
        "btc_base": f"http://{host_ip}:21215",
        "dbg_base": f"http://{host_ip}:21213",
        "bc2_base": "",
        "bch2_base": "",
        "proxy_token": "",
        "discord_webhook": "",
    }
    
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            # Merge loaded data with defaults
            for key in defaults:
                if key in data and data[key]:
                    defaults[key] = data[key]
            
            # Handle conversion from port-based to base URL format
            base_url = defaults.get("base_url", "").strip().rstrip("/")
            if base_url:
                # Build full base URLs from base_url + ports
                if defaults.get("bch_port"):
                    defaults["bch_base"] = f"{base_url}:{defaults['bch_port']}"
                if defaults.get("xec_port"):
                    defaults["xec_base"] = f"{base_url}:{defaults['xec_port']}"
                if defaults.get("btc_port"):
                    defaults["btc_base"] = f"{base_url}:{defaults['btc_port']}"
                if defaults.get("dbg_port"):
                    defaults["dbg_base"] = f"{base_url}:{defaults['dbg_port']}"
                
                # Handle BC2 and BCH2 - can be path or port
                bc2_path = defaults.get("bc2_path", "").strip()
                if bc2_path:
                    if bc2_path.startswith(":"):
                        defaults["bc2_base"] = f"{base_url}{bc2_path}"
                    elif bc2_path.startswith("/"):
                        defaults["bc2_base"] = f"{base_url}{bc2_path}"
                    else:
                        defaults["bc2_base"] = bc2_path
                
                bch2_path = defaults.get("bch2_path", "").strip()
                if bch2_path:
                    if bch2_path.startswith(":"):
                        defaults["bch2_base"] = f"{base_url}{bch2_path}"
                    elif bch2_path.startswith("/"):
                        defaults["bch2_base"] = f"{base_url}{bch2_path}"
                    else:
                        defaults["bch2_base"] = bch2_path
    except Exception:
        pass
    
    # Auto-generate proxy token if JWT_SECRET is available and token is empty
    jwt_secret = os.getenv("JWT_SECRET", DEFAULT_JWT_SECRET).strip()
    if jwt_secret and not defaults.get("proxy_token"):
        defaults["proxy_token"] = generate_umbrel_proxy_token(jwt_secret, 10)
    
    return defaults

def save_config(data):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def check_password(pw):
    if not ADMIN_PASSWORD:
        return True
    return pw == ADMIN_PASSWORD

@app.route("/")
def index():
    pw = request.args.get("pw", "")
    needs_pw = ADMIN_PASSWORD and not check_password(pw)
    cfg = load_config()
    detected_ip = get_host_ip()
    return render_template("index.html", cfg=cfg, needs_pw=needs_pw, detected_ip=detected_ip)

@app.route("/save", methods=["POST"])
def save():
    pw = request.form.get("pw", "")
    if not check_password(pw):
        return redirect("/?pw=" + pw)
    
    # Save the port-based format from the form
    cfg = {
        "base_url": request.form.get("base_url", "").strip(),
        "bch_port": request.form.get("bch_port", "").strip(),
        "xec_port": request.form.get("xec_port", "").strip(),
        "btc_port": request.form.get("btc_port", "").strip(),
        "dbg_port": request.form.get("dbg_port", "").strip(),
        "bc2_path": request.form.get("bc2_path", "").strip(),
        "bch2_path": request.form.get("bch2_path", "").strip(),
        "proxy_token": request.form.get("proxy_token", "").strip(),
        "discord_webhook": request.form.get("discord_webhook", "").strip(),
    }
    save_config(cfg)
    return redirect("/?pw=" + pw)

@app.route("/test", methods=["POST"])
def test_webhook():
    pw = request.form.get("pw", "")
    if not check_password(pw):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    cfg = load_config()
    webhook = cfg.get("discord_webhook", "").strip()
    
    if not webhook:
        return jsonify({"success": False, "error": "Discord webhook not configured"}), 400
    
    chains = [
        ("BCH", cfg.get("bch_base", "").strip()),
        ("XEC", cfg.get("xec_base", "").strip()),
        ("BTC", cfg.get("btc_base", "").strip()),
        ("DBG", cfg.get("dbg_base", "").strip()),
    ]
    
    proxy_token = cfg.get("proxy_token", "").strip()
    cookies = {"UMBREL_PROXY_TOKEN": proxy_token} if proxy_token else None
    
    fields = []
    stats_summary = []
    
    for chain, base_url in chains:
        if not base_url:
            continue
        
        try:
            # Fetch pool stats
            pool_url = f"{base_url.rstrip('/')}/api/pool"
            workers_url = f"{base_url.rstrip('/')}/api/pool/workers"
            
            pool_resp = requests.get(pool_url, cookies=cookies, timeout=10)
            pool_resp.raise_for_status()
            pool_data = pool_resp.json()
            
            workers_resp = requests.get(workers_url, cookies=cookies, timeout=10)
            workers_resp.raise_for_status()
            workers_data = workers_resp.json()
            
            # Extract stats
            workers_details = workers_data.get("workers_details", [])
            workers_count = len(workers_details)
            network_diff = pool_data.get("network_difficulty", 0)
            
            # Calculate hashrate from workers (in TH/s)
            hashrate_ths = 0
            for worker in workers_details:
                hashrate_ths += float(worker.get("hashrate_ths", 0))
            
            # Convert TH/s to H/s for formatting
            hashrate_hs = hashrate_ths * 1_000_000_000_000  # TH to H
            
            # Format numbers
            def format_num(val):
                try:
                    num = float(val)
                    units = ["", "K", "M", "G", "T", "P", "E"]
                    idx = 0
                    while num >= 1000 and idx < len(units) - 1:
                        num /= 1000.0
                        idx += 1
                    return f"{num:.2f}{units[idx]}" if idx > 0 else f"{int(num)}"
                except:
                    return str(val)
            
            hashrate_fmt = format_num(hashrate_hs) + "H/s"
            diff_fmt = format_num(network_diff)
            
            stats_summary.append(f"**{chain}**: {workers_count} workers, {hashrate_fmt}")
            
            # Add field for this chain
            fields.append({
                "name": f"{'✅' if workers_count > 0 else '⚠️'} {chain} Pool",
                "value": f"👷 **Workers:** {workers_count}\n⚡ **Hashrate:** {hashrate_fmt}\n🎯 **Difficulty:** {diff_fmt}",
                "inline": True
            })
            
        except Exception as e:
            stats_summary.append(f"**{chain}**: Offline")
            fields.append({
                "name": f"❌ {chain} Pool",
                "value": "Pool is offline or unreachable.\nMake sure your Axe app is turned on.",
                "inline": True
            })
    
    if not fields:
        return jsonify({"success": False, "error": "No pools configured"}), 400
    
    # Send single embed with all pools
    embed = {
        "title": "🧪 Test Webhook - Current Pool Status",
        "description": "Current status of all configured mining pools",
        "color": 0x667EEA,
        "fields": fields,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "ATH Monitor"}
    }
    
    payload = {"embeds": [embed]}
    
    try:
        resp = requests.post(webhook, json=payload, timeout=15)
        resp.raise_for_status()
        return jsonify({
            "success": True,
            "message": "Test webhook sent successfully!",
            "stats": "\n".join(stats_summary)
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to send webhook: {str(e)}"}), 500

@app.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200

if __name__ == "__main__":
    print("Starting ATH Monitor Web Service...", flush=True)
    
    # Test configuration load
    try:
        cfg = load_config()
        print(f"Configuration loaded. Detected host: {get_host_ip()}", flush=True)
        print(f"Configured endpoints: {len([x for x in cfg.values() if 'http' in str(x)])}", flush=True)
    except Exception as e:
        print(f"Warning: Configuration load failed: {e}", flush=True)
    
    print("Web service ready on port 3456", flush=True)
    
    # Keep the service running with proper error handling
    try:
        app.run(host="0.0.0.0", port=3456, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("Service stopped by user", flush=True)
    except Exception as e:
        print(f"Service error: {e}", flush=True)
        # Don't exit, let Docker restart handle it
        import time
        time.sleep(10)
