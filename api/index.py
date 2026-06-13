"""
ChatGPT Proxy Checker - Vercel Serverless Version
"""
import json
import time
import os
import re
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, send_from_directory
from curl_cffi import requests as cffi_requests

app = Flask(__name__, static_folder='../public', static_url_path='')

# ============================================================
# Configuration
# ============================================================
TIMEOUT = 10
DETECT_TIMEOUT = 6
MAX_CONCURRENT = 20
CHECK_ROUNDS = 2

# Check targets
TARGET_CHAT = "https://chat.openai.com/"
TARGET_SIGNUP = "https://auth0.openai.com/u/signup/authorize?client_id=DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20organization.write&response_type=code&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Flogin-web&audience=https%3A%2F%2Fapi.openai.com%2Fv1&prompt=login&screen_hint=signup"
TARGET_API = "https://api.openai.com/v1/models"
TARGET_IP = "https://api.ipify.org?format=json"

# CF challenge indicators
CF_BODY_INDICATORS = [
    "challenge-platform", "cf_chl_opt", "cf-chl-b", "cf-turnstile",
    "Just a moment", "Checking your browser", "Verify you are human",
    "Enable JavaScript and cookies", "ray ID", "challenge-running",
    "challenges.cloudflare.com", "turnstile.js", "cf-challenge",
    " managed-challenge", "cf_mitigated",
]

OPENAI_REAL_PAGE_INDICATORS = ["__next", "chat.openai.com", "ChatGPT", "prompt-textarea"]
OPENAI_SIGNUP_INDICATORS = ["signup", "auth0", "Create your account", "email", "password", "Sign up"]

executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT)
sessions = {}
sessions_lock = threading.Lock()

# ============================================================
# Helper Functions
# ============================================================
def classify_error(err):
    e = err.lower()
    if "timeout" in e or "timed out" in e: return "连接超时"
    if "refused" in e: return "连接被拒绝"
    if "resolve" in e or "dns" in e: return "DNS解析失败"
    if "socks" in e: return "SOCKS握手失败"
    if "ssl" in e or "certificate" in e: return "SSL/TLS错误"
    if "auth" in e or "407" in e: return "代理需要认证"
    if "connection reset" in e: return "连接被重置"
    return err[:100]

def detect_cf_challenge(resp):
    details = {"cf_detected": False, "cf_challenge_type": None, "cf_indicators": [], "has_real_content": False}
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for k in headers_lower:
        if "cf-ray" in k or "cf-chl" in k:
            details["cf_detected"] = True
            details["cf_indicators"].append(f"header:{k}")
    body = (resp.text or "").lower()
    for ind in CF_BODY_INDICATORS:
        if ind.lower() in body:
            details["cf_detected"] = True
            details["cf_indicators"].append(f"body:{ind}")
    if details["cf_detected"]:
        if "turnstile" in body: details["cf_challenge_type"] = "turnstile"
        elif "managed-challenge" in body or "challenge-platform" in body: details["cf_challenge_type"] = "managed"
        elif "just a moment" in body: details["cf_challenge_type"] = "js"
        elif resp.status_code == 403: details["cf_challenge_type"] = "block"
        else: details["cf_challenge_type"] = "unknown"
    for ind in OPENAI_REAL_PAGE_INDICATORS:
        if ind.lower() in body:
            details["has_real_content"] = True
            break
    return details["cf_detected"], details

def detect_signup_access(resp):
    body = (resp.text or "").lower()
    if resp.status_code == 200:
        for ind in OPENAI_SIGNUP_INDICATORS:
            if ind.lower() in body: return True, "signup_accessible"
        if any(x in body for x in ["challenge-platform", "just a moment"]):
            return False, "cf_challenge_on_signup"
        return True, "signup_200"
    if resp.status_code in (301, 302, 303, 307, 308): return True, f"signup_redirect_{resp.status_code}"
    if resp.status_code == 403: return False, "signup_blocked_403"
    return False, f"signup_error_{resp.status_code}"

def classify_ip_type(ip_info):
    if not ip_info: return "unknown"
    org = (ip_info.get("org") or "").lower()
    for kw in ["amazon", "aws", "google", "cloudflare", "azure", "digitalocean", "linode", "vultr", "hetzner", "ovh", "oracle", "alibaba", "tencent"]:
        if kw in org: return "datacenter"
    return "residential"

def do_check_once(proxy_str, stop_event=None, timeout=TIMEOUT):
    if stop_event and stop_event.is_set():
        return {"valid": False, "error": "已停止"}
    r = {"valid": False, "latency": None, "error": None, "status_code": None, "ip": None, "ip_type": None,
         "api_reachable": None, "cf_bypass": False, "cf_challenge": False, "cf_challenge_type": None,
         "cf_indicators": [], "registration_ready": False, "registration_detail": None, "checks_detail": {}}
    try:
        proxies = {"http": proxy_str, "https": proxy_str}
        # Check chat.openai.com
        try:
            t0 = time.time()
            resp = cffi_requests.get(TARGET_CHAT, proxies=proxies, timeout=timeout, impersonate="chrome", allow_redirects=True)
            r["latency"] = round((time.time() - t0) * 1000)
            r["status_code"] = resp.status_code
            is_cf, cf_details = detect_cf_challenge(resp)
            r["checks_detail"]["chat"] = {"status": resp.status_code, "cf_detected": is_cf, "cf_type": cf_details.get("cf_challenge_type"), "has_content": cf_details.get("has_real_content", False), "size": len(resp.text or "")}
            if resp.status_code in (200, 301, 302, 303, 307, 308):
                if is_cf and not cf_details.get("has_real_content"):
                    r["cf_challenge"] = True; r["cf_challenge_type"] = cf_details.get("cf_challenge_type"); r["cf_indicators"] = cf_details.get("cf_indicators", []); r["valid"] = False; r["error"] = f"CF拦截({cf_details.get('cf_challenge_type', 'unknown')})"
                elif is_cf and cf_details.get("has_real_content"):
                    r["cf_bypass"] = True; r["cf_challenge"] = True; r["cf_challenge_type"] = "soft_challenge"; r["valid"] = True
                else:
                    r["cf_bypass"] = True; r["valid"] = True
            else:
                r["valid"] = False; r["error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            r["error"] = classify_error(str(e)); r["valid"] = False; return r
        if not r["valid"] and not r.get("cf_bypass"): return r
        # Check API
        try:
            ar = cffi_requests.get(TARGET_API, proxies=proxies, timeout=timeout, impersonate="chrome")
            r["api_reachable"] = ar.status_code in (200, 401)
            r["checks_detail"]["api"] = {"status": ar.status_code, "reachable": r["api_reachable"]}
        except: r["api_reachable"] = False; r["checks_detail"]["api"] = {"status": None, "reachable": False}
        # Check signup
        try:
            sr = cffi_requests.get(TARGET_SIGNUP, proxies=proxies, timeout=timeout, impersonate="chrome", allow_redirects=True)
            reg_ok, reg_detail = detect_signup_access(sr)
            r["registration_ready"] = reg_ok; r["registration_detail"] = reg_detail
            r["checks_detail"]["signup"] = {"status": sr.status_code, "accessible": reg_ok, "detail": reg_detail}
        except Exception as e:
            r["registration_ready"] = False; r["registration_detail"] = f"signup_error: {classify_error(str(e))}"
        # Check IP
        for ep in [TARGET_IP]:
            try:
                ir = cffi_requests.get(ep, proxies=proxies, timeout=6, impersonate="chrome")
                if ir.status_code == 200:
                    ip_data = ir.json(); r["ip"] = ip_data.get("ip")
                    if r["ip"]:
                        try:
                            info = cffi_requests.get(f"https://ipinfo.io/{r['ip']}/json", timeout=5, impersonate="chrome")
                            if info.status_code == 200:
                                r["ip_type"] = classify_ip_type(info.json())
                                r["checks_detail"]["ip_info"] = {"ip": r["ip"], "org": info.json().get("org", ""), "country": info.json().get("country", ""), "type": r["ip_type"]}
                        except: r["ip_type"] = "unknown"
                    break
            except: continue
    except Exception as e:
        r["error"] = classify_error(str(e))
    return r

def auto_detect(bare_addr, stop_event=None):
    for prefix in ["http://", "https://", "socks5://", "socks5h://"]:
        if stop_event and stop_event.is_set(): return None, False
        r = do_check_once(prefix + bare_addr, stop_event, DETECT_TIMEOUT)
        if r["valid"] or (r.get("cf_bypass") and r.get("status_code")):
            return prefix + bare_addr, True
    return None, False

def check_proxy_full(proxy_input, stop_event=None, rounds=None):
    if rounds is None: rounds = CHECK_ROUNDS
    proxy_input = proxy_input.strip()
    if not proxy_input or proxy_input.startswith("#"): return None
    if stop_event and stop_event.is_set(): return None
    original = proxy_input
    has_prefix = proxy_input.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://"))
    if not has_prefix:
        proxy_input, found = auto_detect(proxy_input, stop_event)
        if not found:
            return {"proxy": original, "original": original, "valid": False, "unstable": False,
                    "checks_passed": 0, "checks_total": rounds, "error": "所有协议均不可用",
                    "latency": None, "status_code": None, "ip": None, "ip_type": None, "api_reachable": None,
                    "cf_bypass": False, "cf_challenge": False, "cf_challenge_type": None, "cf_indicators": [],
                    "registration_ready": False, "registration_detail": None, "detected_protocol": None,
                    "timestamp": time.time(), "checks_detail": {}, "grade": "F"}
    passed = 0; lats = []; last = None
    for _ in range(rounds):
        if stop_event and stop_event.is_set(): break
        r = do_check_once(proxy_input, stop_event); last = r
        if r["valid"]: passed += 1
        if r.get("latency"): lats.append(r["latency"])
    avg = round(sum(lats) / len(lats)) if lats else (last.get("latency") if last else None)
    proto = proxy_input.split("://")[0] if "://" in proxy_input else None
    chat_ok = passed == rounds; api_ok = last.get("api_reachable") if last else False
    reg_ok = last.get("registration_ready") if last else False; cf_ok = last.get("cf_bypass") if last else False
    if chat_ok and api_ok and reg_ok and cf_ok: grade = "A"
    elif chat_ok and api_ok and cf_ok: grade = "B"
    elif chat_ok and api_ok: grade = "C"
    elif chat_ok: grade = "D"
    else: grade = "F"
    is_valid = chat_ok and api_ok; is_unstable = (chat_ok or api_ok) and not is_valid and passed > 0
    return {"proxy": proxy_input, "original": original, "valid": is_valid, "unstable": is_unstable,
            "grade": grade, "checks_passed": passed, "checks_total": rounds,
            "error": last["error"] if last and not last["valid"] else None, "latency": avg,
            "status_code": last["status_code"] if last else None, "ip": last["ip"] if last else None,
            "ip_type": last["ip_type"] if last else None, "api_reachable": last["api_reachable"] if last else None,
            "cf_bypass": last["cf_bypass"] if last else False, "cf_challenge": last["cf_challenge"] if last else False,
            "cf_challenge_type": last["cf_challenge_type"] if last else None, "cf_indicators": last["cf_indicators"] if last else [],
            "registration_ready": last["registration_ready"] if last else False,
            "registration_detail": last["registration_detail"] if last else None,
            "detected_protocol": proto, "timestamp": time.time(), "checks_detail": last["checks_detail"] if last else {}}

def run_check(session_id, proxies, rounds=None):
    if rounds is None: rounds = CHECK_ROUNDS
    with sessions_lock: sessions[session_id]["stop"] = threading.Event()
    stop_event = sessions[session_id]["stop"]
    def check_one(proxy):
        if stop_event.is_set(): return None
        r = check_proxy_full(proxy, stop_event=stop_event, rounds=rounds)
        if r:
            with sessions_lock:
                s = sessions.get(session_id)
                if s: s["results"].append(r); s["done"] += 1
        return r
    loop = asyncio.new_event_loop()
    try:
        tasks = [loop.run_in_executor(executor, check_one, p) for p in proxies]
        loop.run_until_complete(asyncio.gather(*tasks))
    finally: loop.close()
    with sessions_lock:
        s = sessions.get(session_id)
        if s: s["finished"] = True

# ============================================================
# Session cleanup
# ============================================================
def cleanup_sessions():
    while True:
        time.sleep(120)
        now = time.time()
        with sessions_lock:
            to_del = [k for k, v in sessions.items() if v.get("finished") and now - v.get("created", now) > 600]
            for k in to_del: del sessions[k]

threading.Thread(target=cleanup_sessions, daemon=True).start()

# ============================================================
# Flask Routes
# ============================================================
@app.route('/')
def index():
    return send_from_directory('../public', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../public', path)

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.get_json(force=True) or {}
    proxies = data.get("proxies", [])
    rounds = max(1, min(5, int(data.get("rounds", CHECK_ROUNDS))))
    sid = str(time.time()) + str(id(proxies))
    with sessions_lock:
        sessions[sid] = {"results": [], "done": 0, "finished": False, "stop": None, "total": len(proxies), "created": time.time(), "rounds": rounds}
    threading.Thread(target=run_check, args=(sid, proxies, rounds), daemon=True).start()
    return jsonify({"session_id": sid, "total": len(proxies), "rounds": rounds})

@app.route('/api/status', methods=['POST'])
def api_status():
    data = request.get_json(force=True) or {}
    sid = data.get("session_id", ""); since = data.get("since", 0)
    with sessions_lock:
        s = sessions.get(sid)
        if not s: return jsonify({"error": "not found"})
        all_r = s["results"]; new_r = all_r[since:]
        return jsonify({"new": new_r, "total_done": s["done"], "total": s["total"], "finished": s["finished"],
                        "valid_count": sum(1 for r in all_r if r.get("valid")),
                        "unstable_count": sum(1 for r in all_r if r.get("unstable")),
                        "invalid_count": sum(1 for r in all_r if not r.get("valid") and not r.get("unstable")),
                        "cf_bypass_count": sum(1 for r in all_r if r.get("cf_bypass")),
                        "registration_count": sum(1 for r in all_r if r.get("registration_ready"))})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    data = request.get_json(force=True) or {}
    sid = data.get("session_id", "")
    with sessions_lock:
        s = sessions.get(sid)
        if s and s.get("stop"): s["stop"].set()
    return jsonify({"ok": True})

@app.route('/api/capabilities', methods=['POST'])
def api_capabilities():
    try:
        from fetch_proxies import PROXY_SOURCES
        sources = [{"id": s["id"], "name": s["name"]} for s in PROXY_SOURCES]
        return jsonify({"nodriver": False, "xvfb": False, "deep_check": False, "fetch_proxies": True, "proxy_sources": sources, "hosted": "vercel"})
    except ImportError:
        return jsonify({"nodriver": False, "xvfb": False, "deep_check": False, "fetch_proxies": False, "proxy_sources": [], "hosted": "vercel"})

@app.route('/api/fetch-proxies', methods=['POST'])
def api_fetch_proxies():
    try:
        from fetch_proxies import fetch_proxies
    except ImportError:
        return jsonify({"error": "fetch_proxies 模块不可用"})
    data = request.get_json(force=True) or {}
    source_id = data.get("source", "proxifly")
    limit = min(int(data.get("limit", 500)), 2000)
    proxies, source_name, err = fetch_proxies(source_id, limit)
    if err:
        return jsonify({"error": err, "source": source_name})
    return jsonify({"proxies": proxies, "count": len(proxies), "source": source_name, "source_id": source_id})

# Vercel WSGI handler
app = app
