import os
import time
import json
import requests
import threading
import sys
import base64
import hmac
import hashlib
from typing import Any, Dict
from datetime import datetime, timezone, timedelta

CONFIG_PATH = "/data/config.json"

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "15"))

LOG_LOCK = threading.Lock()


def log(message: str, chain: str | None = None) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prefix = f"[{timestamp}]"
    if chain:
        prefix = f"{prefix} [{chain}]"
    with LOG_LOCK:
        print(f"{prefix} {message}", flush=True)
        sys.stdout.flush()


log("=" * 50)
log("ATH Monitor Watcher Starting...")
log("=" * 50)

# Hardcoded JWT secret for proxy token generation (fallback if JWT_SECRET env var not set)
DEFAULT_JWT_SECRET = "fd820bbcbbc6cc59a0ce68a8b4914b3763bba0da557ba30dc9c884d4b4a2a0b9"

# -----------------------------
# JWT Token Generation Helper
# -----------------------------

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

# -----------------------------
# Config Loader
# -----------------------------

def load_config() -> Dict[str, str]:
    defaults = {
        "base_url": "",
        "bch_port": "",
        "xec_port": "",
        "btc_port": "",
        "dbg_port": "",
        "bc2_path": "",
        "bch2_path": "",
        "bch_base": "",
        "xec_base": "",
        "btc_base": "",
        "dbg_base": "",
        "dbg_algos": "sha256,scrypt",
        "bc2_base": "",
        "bch2_base": "",
        "proxy_token": "",
        "discord_webhook": "",
    }

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k in defaults:
                if k in data and data[k] is not None:
                    defaults[k] = str(data[k]).strip()
            
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

    # Normalize URLs
    for k in ("bch_base", "xec_base", "btc_base", "dbg_base", "bc2_base", "bch2_base"):
        defaults[k] = defaults[k].rstrip("/")

    # Auto-generate proxy token if JWT_SECRET is available and token is empty
    jwt_secret = os.getenv("JWT_SECRET", DEFAULT_JWT_SECRET).strip()
    if jwt_secret and not defaults.get("proxy_token"):
        defaults["proxy_token"] = generate_umbrel_proxy_token(jwt_secret, 10)

    return defaults


# -----------------------------
# Utilities
# -----------------------------

def format_mining_number(value: int) -> str:
    try:
        num = float(value)
    except Exception:
        return str(value)

    units = ["", "K", "M", "G", "T", "P", "E"]
    index = 0
    while num >= 1000 and index < len(units) - 1:
        num /= 1000.0
        index += 1

    return f"{int(num)}" if index == 0 else f"{num:.2f}{units[index]}"


def progress_bar(ratio: float, width: int = 18) -> str:
    ratio = max(0.0, ratio)
    filled = int(min(ratio, 1.0) * width)
    empty = width - filled
    bar = "█" * filled + "░" * empty
    pct = min(ratio, 1.0) * 100
    return f"`{bar}` **{pct:.2f}%**"


def shorten_text(text: str, limit: int = 400) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def summarize_workers(details: list[Dict[str, Any]], limit: int = 5) -> str:
    names = []
    for worker in details[:limit]:
        raw_name = str(worker.get("workername", "")).strip()
        if raw_name:
            names.append(pretty_worker_name(raw_name))
    if not names:
        return "no named workers"
    suffix = "" if len(details) <= limit else f" ... +{len(details) - limit} more"
    return ", ".join(names) + suffix


def summarize_names(names: list[str], limit: int = 5) -> str:
    pretty_names = [pretty_worker_name(name) for name in names[:limit]]
    if not pretty_names:
        return "none"
    suffix = "" if len(names) <= limit else f" ... +{len(names) - limit} more"
    return ", ".join(pretty_names) + suffix


def get_json(url: str, proxy_token: str) -> Dict[str, Any]:
    cookies = {"UMBREL_PROXY_TOKEN": proxy_token} if proxy_token else None
    r = requests.get(
        url,
        cookies=cookies,
        headers={"Accept": "application/json"},
        timeout=15,
    )

    try:
        r.raise_for_status()
    except requests.HTTPError as exc:
        body = ""
        try:
            body_text = shorten_text(r.text)
            if body_text:
                body = f" | body: {body_text}"
        except Exception:
            pass
        raise RuntimeError(f"HTTP {r.status_code} for {url}{body}") from exc

    try:
        data = r.json()
    except ValueError as exc:
        body_text = shorten_text(r.text)
        body = f" | body: {body_text}" if body_text else ""
        raise RuntimeError(f"Invalid JSON from {url}{body}") from exc

    return data if isinstance(data, dict) else {"_raw": data}


def pretty_worker_name(workername: str) -> str:
    if not workername:
        return "Unknown"
    suffix = workername.split(".", 1)[1] if "." in workername else workername
    suffix = " ".join(suffix.strip().split())
    return suffix.title() if suffix else "Unknown"


# -----------------------------
# Discord
# -----------------------------

def discord_post_ath(display: str, bestever: int, worker_data: Dict[str, Any],
                     pool_data: Dict[str, Any], chain: str,
                     webhook: str):

    if not webhook:
        log("Discord webhook not set", chain)
        return

    colors = {
        "BCH": 706958,
        "XEC": 0x0074C2,
        "BTC": 0xF7931A,
        "DBG": 0x8B4513,
        "BC2": 0x3498DB,
        "BCH2": 0x27AE60,
    }

    thumbnails = {
        "BCH": "https://cryptologos.cc/logos/bitcoin-cash-bch-logo.png",
        "XEC": "https://cryptologos.cc/logos/ecash-xec-logo.png",
        "BTC": "https://cryptologos.cc/logos/bitcoin-btc-logo.png",
        "DBG": "https://via.placeholder.com/150/8B4513/FFFFFF?text=DBG",
        "BC2": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQH9BaF35g1hAM-MMgOHHxMsQSB42NiO1u2kw&s",
        "BCH2": "https://github.com/AkaCurtis/Axe-Webhooks/blob/main/images-removebg-preview.png?raw=true",
    }

    embed_color = colors.get(chain, 706958)
    thumbnail = thumbnails.get(chain)

    best_formatted = format_mining_number(bestever)

    diff = pool_data.get("network_difficulty")
    diff_int = None
    diff_formatted = "—"

    try:
        if diff:
            diff_int = int(float(diff))
            diff_formatted = format_mining_number(diff_int)
    except Exception:
        pass

    ratio = float(bestever) / float(diff_int) if diff_int else 0.0
    bar_text = progress_bar(ratio)

    fields = [
        {"name": "🏷 Worker", "value": f"**{display}**", "inline": True},
        {"name": "🎯 Best Share", "value": f"`{best_formatted}`", "inline": True},
        {"name": "⛏ Block Diff", "value": f"`{diff_formatted}`", "inline": True},
        {"name": "📈 Progress to Block", "value": bar_text, "inline": False},
    ]

    # Check if worker hit 100% (found a block!)
    if ratio >= 1.0:
        embed_title = f"🎉 {display} just hit a block! ({chain})"
        embed_description = f"**{display}** found a block with this share! Congratulations! 🎊"
        embed_image = "https://media.tenor.com/_R_724_kn-AAAAAM/kirby-jams.gif"
    else:
        embed_title = f"🔥 NEW WORKER ATH! ({chain})"
        embed_description = f"**{display}** just hit a new best share!"
        embed_image = None

    embed_data = {
        "title": embed_title,
        "description": embed_description,
        "color": embed_color,
        "thumbnail": {"url": thumbnail},
        "fields": fields,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"Axe{chain} Solo Node"},
    }

    # Add Kirby gif if they hit a block
    if embed_image:
        embed_data["image"] = {"url": embed_image}

    payload = {
        "username": f"Axe{chain} Monitor",
        "avatar_url": thumbnail,
        "embeds": [embed_data]
    }

    r = requests.post(webhook, json=payload, timeout=15)
    r.raise_for_status()


# -----------------------------
# Monitor Logic
# -----------------------------

def monitor_chain_algo(chain: str, base_key: str, algo: str):
    """Monitor a specific algorithm on a multi-algo chain."""
    display_chain = f"{chain}-{algo.upper()}"
    state_file = f"/data/{chain.lower()}_{algo.lower()}_state.json"

    cycle_best: Dict[str, int] = {}

    try:
        with open(state_file, "r") as f:
            d = json.load(f)
            if isinstance(d, dict):
                stored_cycle_best = d.get("cycle_best")
                legacy_cycle_best = d.get("last_bestever")
                raw_cycle_best = stored_cycle_best if isinstance(stored_cycle_best, dict) else legacy_cycle_best
                if isinstance(raw_cycle_best, dict):
                    cycle_best = {
                        str(worker): int(value)
                        for worker, value in raw_cycle_best.items()
                    }
    except Exception:
        pass

    log("Monitor started", display_chain)

    if cycle_best:
        log("Stored cycle best values from state file:", display_chain)
        for worker, ath in cycle_best.items():
            log(f"{pretty_worker_name(worker)}: {format_mining_number(ath)}", display_chain)
    else:
        log("No stored cycle values yet", display_chain)

    while True:
        try:
            cfg = load_config()

            base_url = cfg[base_key]
            proxy_token = cfg["proxy_token"]
            webhook = cfg["discord_webhook"]

            if not base_url or base_url.strip() == "":
                log("Skipping poll because no URL is configured", display_chain)
                time.sleep(POLL_SECONDS)
                continue

            # Multi-algo uses /api/pool/miners?algo=<algo>
            workers_url = f"{base_url}/api/pool/miners?algo={algo}"
            pool_url = f"{base_url}/api/pool"

            log(f"Polling {base_url} (algo={algo})", display_chain)

            workers_data = get_json(workers_url, proxy_token)
            pool_data = get_json(pool_url, proxy_token)

            # Multi-algo API uses 'miners' key
            details = workers_data.get("miners", [])
            if not isinstance(details, list):
                details = []

            log(f"Fetched {len(details)} miners: {summarize_workers(details)}", display_chain)

            current_best: Dict[str, int] = {}
            for w in details:
                raw_name = str(w.get("workername", "")).strip()
                if not raw_name:
                    continue

                bestever = w.get("bestshare_since_block")
                if bestever is None:
                    continue

                try:
                    current_best[raw_name] = int(bestever)
                except Exception:
                    continue

            if current_best:
                log("Current ATH from pool API:", display_chain)
                for raw_name, bestever_int in current_best.items():
                    stored = cycle_best.get(raw_name)
                    stored_text = format_mining_number(stored) if stored is not None else "none"
                    log(
                        f"  {pretty_worker_name(raw_name)}: "
                        f"{format_mining_number(bestever_int)} (tracking) [stored: {stored_text}]",
                        display_chain,
                    )

            changed = False

            for w in details:
                raw_name = str(w.get("workername", "")).strip()
                if not raw_name:
                    continue

                bestever_int = current_best.get(raw_name)
                if bestever_int is None:
                    continue

                prev = cycle_best.get(raw_name)

                if prev is None:
                    log(
                        f"Tracking new worker {pretty_worker_name(raw_name)} at "
                        f"{format_mining_number(bestever_int)}",
                        display_chain,
                    )
                    cycle_best[raw_name] = bestever_int
                    changed = True
                    continue

                prev_int = int(prev)

                # Reset detected: worker found a block or reset stats
                if bestever_int < prev_int:
                    log(
                        f"Reset detected for {pretty_worker_name(raw_name)}: "
                        f"{format_mining_number(prev_int)} -> {format_mining_number(bestever_int)}. "
                        f"Re-basing tracker.",
                        display_chain,
                    )
                    cycle_best[raw_name] = bestever_int
                    changed = True
                    continue

                # New best in current cycle
                if bestever_int > prev_int:
                    display = pretty_worker_name(raw_name)
                    log(
                        f"Cycle best increased for {display}: "
                        f"{format_mining_number(prev_int)} -> {format_mining_number(bestever_int)}",
                        display_chain,
                    )

                    try:
                        discord_post_ath(display, bestever_int, w, pool_data, display_chain, webhook)
                        log(f"Discord alert sent for {display}", display_chain)
                    except Exception as e:
                        log(f"Discord alert failed for {display}: {e}", display_chain)

                    cycle_best[raw_name] = bestever_int
                    changed = True

            if changed:
                with open(state_file + ".tmp", "w") as f:
                    json.dump({"cycle_best": cycle_best}, f)
                os.replace(state_file + ".tmp", state_file)
                log(f"Saved state for {len(cycle_best)} miners", display_chain)

        except Exception as e:
            log(f"Poll failed: {e}", display_chain)

        time.sleep(POLL_SECONDS)


def monitor_chain(chain: str, base_key: str):

    state_file = f"/data/{chain.lower()}_state.json"

    cycle_best: Dict[str, int] = {}

    try:
        with open(state_file, "r") as f:
            d = json.load(f)
            if isinstance(d, dict):
                stored_cycle_best = d.get("cycle_best")
                legacy_cycle_best = d.get("last_bestever")
                raw_cycle_best = stored_cycle_best if isinstance(stored_cycle_best, dict) else legacy_cycle_best
                if isinstance(raw_cycle_best, dict):
                    cycle_best = {
                        str(worker): int(value)
                        for worker, value in raw_cycle_best.items()
                    }
    except Exception:
        pass

    log("Monitor started", chain)

    if cycle_best:
        log("Stored cycle best values from state file:", chain)
        for worker, ath in cycle_best.items():
            log(f"{pretty_worker_name(worker)}: {format_mining_number(ath)}", chain)
    else:
        log("No stored cycle values yet", chain)

    while True:
        try:
            cfg = load_config()

            base_url = cfg[base_key]
            proxy_token = cfg["proxy_token"]
            webhook = cfg["discord_webhook"]

            if not base_url or base_url.strip() == "":
                log("Skipping poll because no URL is configured", chain)
                time.sleep(POLL_SECONDS)
                continue

            workers_url = f"{base_url}/api/pool/workers"
            pool_url = f"{base_url}/api/pool"

            log(f"Polling {base_url}", chain)

            workers_data = get_json(workers_url, proxy_token)
            pool_data = get_json(pool_url, proxy_token)

            details = workers_data.get("workers_details", [])
            if not isinstance(details, list):
                details = []

            log(f"Fetched {len(details)} workers: {summarize_workers(details)}", chain)

            current_best: Dict[str, int] = {}
            for w in details:
                raw_name = str(w.get("workername", "")).strip()
                if not raw_name:
                    continue

                bestever = w.get("bestshare_since_block")
                if bestever is None:
                    continue

                try:
                    current_best[raw_name] = int(bestever)
                except Exception:
                    continue

            if current_best:
                log("Current ATH from pool API:", chain)
                for raw_name, bestever_int in current_best.items():
                    stored = cycle_best.get(raw_name)
                    stored_text = format_mining_number(stored) if stored is not None else "none"
                    log(
                        f"  {pretty_worker_name(raw_name)}: "
                        f"{format_mining_number(bestever_int)} (tracking) [stored: {stored_text}]",
                        chain,
                    )

            changed = False

            for w in details:
                raw_name = str(w.get("workername", "")).strip()
                if not raw_name:
                    continue

                bestever_int = current_best.get(raw_name)
                if bestever_int is None:
                    continue

                prev = cycle_best.get(raw_name)

                if prev is None:
                    log(
                        f"Tracking new worker {pretty_worker_name(raw_name)} at "
                        f"{format_mining_number(bestever_int)}",
                        chain,
                    )
                    cycle_best[raw_name] = bestever_int
                    changed = True
                    continue

                prev_int = int(prev)

                # Reset detected: worker found a block or reset stats
                if bestever_int < prev_int:
                    log(
                        f"Reset detected for {pretty_worker_name(raw_name)}: "
                        f"{format_mining_number(prev_int)} -> {format_mining_number(bestever_int)}. "
                        f"Re-basing tracker.",
                        chain,
                    )
                    cycle_best[raw_name] = bestever_int
                    changed = True
                    continue

                # New best in current cycle
                if bestever_int > prev_int:
                    display = pretty_worker_name(raw_name)
                    log(
                        f"Cycle best increased for {display}: "
                        f"{format_mining_number(prev_int)} -> {format_mining_number(bestever_int)}",
                        chain,
                    )

                    try:
                        discord_post_ath(display, bestever_int, w, pool_data, chain, webhook)
                        log(f"Discord alert sent for {display}", chain)
                    except Exception as e:
                        log(f"Discord alert failed for {display}: {e}", chain)

                    cycle_best[raw_name] = bestever_int
                    changed = True

            if changed:
                with open(state_file + ".tmp", "w") as f:
                    json.dump({"cycle_best": cycle_best}, f)
                os.replace(state_file + ".tmp", state_file)
                log(f"Saved state for {len(cycle_best)} workers", chain)

        except Exception as e:
            log(f"Poll failed: {e}", chain)

        time.sleep(POLL_SECONDS)


# -----------------------------
# Main
# -----------------------------

def main():
    log("Multi-Chain ATH Monitor")
    log(f"Polling every {POLL_SECONDS}s")
    log("=" * 40)

    threads = [
        threading.Thread(target=monitor_chain, args=("BCH", "bch_base"), daemon=True),
        threading.Thread(target=monitor_chain, args=("XEC", "xec_base"), daemon=True),
        threading.Thread(target=monitor_chain, args=("BTC", "btc_base"), daemon=True),
        threading.Thread(target=monitor_chain, args=("BC2", "bc2_base"), daemon=True),
        threading.Thread(target=monitor_chain, args=("BCH2", "bch2_base"), daemon=True),
    ]

    # DGB multi-algo monitoring
    cfg = load_config()
    dbg_algos = cfg.get("dbg_algos", "sha256,scrypt")
    for algo in dbg_algos.split(","):
        algo = algo.strip()
        if algo:
            threads.append(
                threading.Thread(target=monitor_chain_algo, args=("DBG", "dbg_base", algo), daemon=True)
            )

    for t in threads:
        t.start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    try:
        log("Starting main()...")
        main()
    except Exception as e:
        log(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
