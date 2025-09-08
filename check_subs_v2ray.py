#!/usr/bin/env python3
import asyncio, json, tempfile, os, base64, argparse, re
from urllib.parse import urlparse, unquote, parse_qs
import aiohttp

def safe_b64decode(s):
    s2 = s.strip()
    pad = (-len(s2)) % 4
    return base64.urlsafe_b64decode(s2 + "="*pad)

def extract_entries(sub_content: str):
    """Decode sub URL response menjadi list vmess:// vless:// trojan://"""
    try:
        decoded = safe_b64decode(sub_content).decode("utf-8", errors="ignore")
        if "vmess://" in decoded or "vless://" in decoded or "trojan://" in decoded:
            return [x.strip() for x in decoded.splitlines() if x.strip()]
    except Exception:
        pass
    return [x.strip() for x in sub_content.splitlines() if x.strip()]

def parse_entry(uri):
    """Parse vmess/vless/trojan uri ke dict sederhana"""
    if uri.startswith("vmess://"):
        raw = uri[8:]
        data = json.loads(safe_b64decode(raw).decode())
        return {
            "protocol": "vmess",
            "server": data["add"],
            "port": int(data["port"]),
            "id": data["id"],
            "security": data.get("scy", "auto"),
            "alterId": int(data.get("aid", 0)),
            "remark": data.get("ps", "")
        }
    else:
        u = urlparse(uri)
        qs = parse_qs(u.query)
        return {
            "protocol": u.scheme,
            "server": u.hostname,
            "port": u.port,
            "id": u.username,   # untuk vless biasanya UUID
            "password": u.password,
            "remark": unquote(u.fragment) if u.fragment else ""
        }

def build_config(entry):
    """Bangun config.json sesuai protokol"""
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
    else:
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
            v2ray_bin, "run", "-c", fname,
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

async def main(args):
    async with aiohttp.ClientSession() as sess:
        async with sess.get(args.suburl, timeout=15) as r:
            content = await r.text()
    entries_raw = extract_entries(content)
    print(f"Fetched {len(entries_raw)} entries from {args.suburl}")
    parsed = [parse_entry(e) for e in entries_raw]

    results = []
    for p in parsed:
        ok = await test_entry(p, args.v2ray, timeout=args.timeout)
        results.append({
            "protocol": p["protocol"],
            "server": p["server"],
            "port": p["port"],
            "remark": p.get("remark", ""),
            "status": "active" if ok else "inactive"
        })
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--suburl", required=True, help="Subscription URL")
    parser.add_argument("--v2ray", default="./v2ray", help="Path ke binary v2ray")
    parser.add_argument("--timeout", type=int, default=8)
    args = parser.parse_args()
    asyncio.run(main(args))
