#!/usr/bin/env python3
import asyncio, json, tempfile, os, base64
from urllib.parse import urlparse, unquote
import aiohttp

SUB_URL = "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub8.txt"

def safe_b64decode(s):
    s2 = s.strip()
    pad = (-len(s2)) % 4
    return base64.urlsafe_b64decode(s2 + "="*pad)

def extract_entries(sub_content: str):
    try:
        decoded = safe_b64decode(sub_content).decode("utf-8", errors="ignore")
        if any(proto in decoded for proto in ["vmess://", "vless://", "trojan://"]):
            return [x.strip() for x in decoded.splitlines() if x.strip()]
    except Exception:
        pass
    return [x.strip() for x in sub_content.splitlines() if x.strip()]

def parse_entry(uri):
    if uri.startswith("vmess://"):
        raw = uri[8:]
        data = json.loads(safe_b64decode(raw).decode())
        return {
            "protocol": "vmess",
            "server": data["add"],
            "port": int(data["port"]),
            "id": data["id"],
            "alterId": int(data.get("aid", 0)),
            "security": data.get("scy", "auto"),
            "remark": data.get("ps", ""),
            "uri": uri
        }
    else:
        u = urlparse(uri)
        return {
            "protocol": u.scheme,
            "server": u.hostname,
            "port": u.port,
            "id": u.username,
            "password": u.password,
            "remark": unquote(u.fragment) if u.fragment else "",
            "uri": uri
        }

def build_config(entry):
    if entry["protocol"] == "vmess":
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [{
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": entry["server"],
                        "port": entry["port"],
                        "users": [{
                            "id": entry["id"],
                            "alterId": entry["alterId"],
                            "security": entry["security"]
                        }]
                    }]
                }
            }]
        }
    elif entry["protocol"] == "vless":
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": entry["server"],
                        "port": entry["port"],
                        "users": [{
                            "id": entry["id"],
                            "encryption": "none"
                        }]
                    }]
                }
            }]
        }
    elif entry["protocol"] == "trojan":
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [{
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": entry["server"],
                        "port": entry["port"],
                        "password": entry["password"]
                    }]
                }
            }]
        }
    return None

async def test_entry(entry, v2ray_bin, timeout=8):
    cfg = build_config(entry)
    if not cfg:
        return False
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(cfg, f)
        fname = f.name
    try:
        proc = await asyncio.create_subprocess_exec(
            v2ray_bin, "-c", fname,   # FIX: tidak pakai "run"
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            code = proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            return False
        return code == 0
    finally:
        os.remove(fname)

async def main():
    async with aiohttp.ClientSession() as sess:
        async with sess.get(SUB_URL, timeout=15) as r:
            content = await r.text()
    entries_raw = extract_entries(content)
    parsed = [parse_entry(e) for e in entries_raw]

    # hasil akhir hanya link aktif
    with open("results.txt", "w", encoding="utf-8") as f:
        for p in parsed:
            ok = await test_entry(p, "./v2ray/v2ray", timeout=8)
            if ok:
                f.write(p["uri"] + "\n")

if __name__ == "__main__":
    asyncio.run(main())
