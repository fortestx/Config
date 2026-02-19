#!/usr/bin/env python3
"""
GitHub Action Script - GitLab Upload Version
- Duplicate detection basit (string bazlı)
- Rename aktif (emoji + ülke kodu + protokol)
- vmess base64 ps update destekli
- Çıktı GitLab repo içine commit edilir
"""

import os
import sys
import asyncio
import aiohttp
import re
import json
import base64
import urllib.parse

sys.stdout.reconfigure(encoding='utf-8')

##################################################
# ENV
##################################################

CONFIG_URLS = os.getenv("CONFIG_URLS")

GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "glpat-9cWg7jJR-WTnu4Ufl3Zq3286MQp1OmtsZTk1Cw.01.12010dkca")
GITLAB_PROJECT_ID = os.getenv("GITLAB_PROJECT_ID")
GITLAB_BRANCH = os.getenv("GITLAB_BRANCH", "main")
GITLAB_OUTPUT_FILE = os.getenv("GITLAB_OUTPUT_FILE", "working_configs.txt")

GITLAB_API_BASE = "https://gitlab.com/api/v4"

MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
ENABLE_RENAME = os.getenv("ENABLE_RENAME", "true").lower() == "true"

rename_counter = {}

##################################################
# HELPERS
##################################################

def safe_b64_decode(s):
    try:
        s = s.strip().replace("-", "+").replace("_", "/")
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except:
        return ""

##################################################
# RENAME
##################################################

def rename_config_simple(link):
    if not ENABLE_RENAME:
        return link

    proto = link.split("://")[0].lower()

    if '#' in link:
        base_config = link.split('#')[0]
        fragment = link.split('#', 1)[1]
    else:
        base_config = link
        fragment = ""

    vmess_data = None
    if proto == "vmess" and not fragment:
        try:
            decoded = safe_b64_decode(link.replace("vmess://", ""))
            if decoded:
                vmess_data = json.loads(decoded)
                ps = vmess_data.get("ps", "")
                if ps:
                    fragment = urllib.parse.unquote(ps)
        except:
            pass

    emoji_pattern = re.compile(r'([\U0001F1E6-\U0001F1FF]{2}|[\U0001F300-\U0001F9FF])')
    emoji_match = emoji_pattern.search(fragment)

    if not emoji_match:
        key = proto
        rename_counter[key] = rename_counter.get(key, 0) + 1
        new_name = f"{proto}{rename_counter[key]}"

        if proto == "vmess" and vmess_data is not None:
            try:
                vmess_data["ps"] = new_name
                new_json = json.dumps(vmess_data, separators=(',', ':'), ensure_ascii=False)
                new_b64 = base64.b64encode(new_json.encode()).decode()
                return f"vmess://{new_b64}"
            except:
                pass

        return f"{base_config}#{new_name}"

    flag_emoji = emoji_match.group(1)

    if len(flag_emoji) == 2 and '\U0001F1E6' <= flag_emoji[0] <= '\U0001F1FF':
        code_points = [ord(c) - 0x1F1E6 + ord('A') for c in flag_emoji]
        country_code = ''.join(chr(c) for c in code_points)

        country_map = {
            "JP": "JAP", "US": "USA", "DE": "GER", "GB": "GBR", "FR": "FRA",
            "TR": "TUR", "NL": "NLD", "SG": "SGP", "CA": "CAN", "HK": "HKG"
        }

        country_3 = country_map.get(country_code, country_code)

        key = f"{flag_emoji}_{country_3}_{proto}"
        rename_counter[key] = rename_counter.get(key, 0) + 1
        new_name = f"{flag_emoji}{country_3}-{proto}{rename_counter[key]}"
    else:
        key = f"{flag_emoji}_{proto}"
        rename_counter[key] = rename_counter.get(key, 0) + 1
        new_name = f"{flag_emoji}{proto}{rename_counter[key]}"

    if proto == "vmess" and vmess_data is not None:
        try:
            vmess_data["ps"] = new_name
            new_json = json.dumps(vmess_data, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json.encode()).decode()
            return f"vmess://{new_b64}"
        except:
            pass

    return f"{base_config}#{new_name}"

##################################################
# URL PARSE
##################################################

def parse_urls(raw_urls):
    if not raw_urls:
        return []

    urls = []
    for line in raw_urls.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    return list(dict.fromkeys(urls))

##################################################
# FETCH
##################################################

async def fetch_configs_from_url(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=45)) as resp:
            if resp.status != 200:
                print(f"[!] HTTP {resp.status}: {url}")
                return []

            raw_data = await resp.text()
            configs = []
            supported = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://']

            for line in raw_data.splitlines():
                line = line.strip()
                if any(p in line for p in supported):
                    configs.append(line)

            print(f"[+] {len(configs)} config bulundu: {url}")
            return configs

    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

async def fetch_all_configs():
    url_list = parse_urls(CONFIG_URLS)
    if not url_list:
        print("[!] Geçerli URL yok")
        return None

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_configs_from_url(session, u) for u in url_list]
        results = await asyncio.gather(*tasks)

    all_configs = []
    for r in results:
        all_configs.extend(r)

    return list(dict.fromkeys(all_configs))

##################################################
# GITLAB UPLOAD
##################################################

async def gitlab_upload(content):
    if not GITLAB_TOKEN or not GITLAB_PROJECT_ID:
        print("[!] GITLAB_TOKEN veya GITLAB_PROJECT_ID eksik")
        return False

    headers = {
        "PRIVATE-TOKEN": GITLAB_TOKEN,
        "Content-Type": "application/json"
    }

    file_path_encoded = urllib.parse.quote(GITLAB_OUTPUT_FILE, safe="")
    file_url = f"{GITLAB_API_BASE}/projects/{GITLAB_PROJECT_ID}/repository/files/{file_path_encoded}"

    async with aiohttp.ClientSession() as session:

        async with session.get(file_url, headers=headers, params={"ref": GITLAB_BRANCH}) as check:
            exists = check.status == 200

        payload = {
            "branch": GITLAB_BRANCH,
            "content": content,
            "commit_message": "Auto update working configs"
        }

        if exists:
            async with session.put(file_url, headers=headers, json=payload) as resp:
                if resp.status == 200:
                    print("[+] Dosya güncellendi")
                    return True
                else:
                    print("[!] Update hatası:", resp.status)
                    print(await resp.text())
                    return False
        else:
            async with session.post(file_url, headers=headers, json=payload) as resp:
                if resp.status == 201:
                    print("[+] Dosya oluşturuldu")
                    return True
                else:
                    print("[!] Create hatası:", resp.status)
                    print(await resp.text())
                    return False

##################################################
# MAIN
##################################################

async def main():
    print("🚀 GitLab Config Updater")

    if not CONFIG_URLS or not GITLAB_TOKEN:
        print("[!] CONFIG_URLS veya GITLAB_TOKEN eksik")
        sys.exit(1)

    configs = await fetch_all_configs()
    if not configs:
        print("[!] Hiç config bulunamadı")
        sys.exit(1)

    renamed = [rename_config_simple(c) for c in configs]
    content = "\n".join(renamed)

    success = await gitlab_upload(content)

    if success:
        print(f"[+] ✅ {len(renamed)} config yüklendi")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
