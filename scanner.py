import os
import sys
import asyncio
import aiohttp
import base64
import json
import re

# UTF-8 ayarı
sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar
CONFIG_URL = os.getenv("CONFIG_URL")
PCLOUD_AUTH = os.getenv("PCLOUD_AUTH")
API_BASE = "https://eapi.pcloud.com"

MAX_CONFIG = 2000 # 2000 bulunca durur
TIMEOUT = 4
CONCURRENT = 400 # 10.000 config için hızı artırdık

# Ülke Bayrak Sözlüğü
FLAGS = {
    "TR": "🇹🇷", "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", 
    "NL": "🇳🇱", "SG": "🇸🇬", "JP": "🇯🇵", "CA": "🇨🇦", "HK": "🇭🇰"
}
rename_counter = {}
working_list = []
stop_event = asyncio.Event()

# ---------------- PARSERS ---------------- #
def parse_host_port(config):
    try:
        if config.startswith(("vless://", "trojan://")):
            match = re.search(r'@([^:]+):(\d+)', config)
            if match: return match.group(1), int(match.group(2))
        elif config.startswith("vmess://"):
            data = json.loads(base64.b64decode(config.replace("vmess://", "") + "==").decode())
            return data.get("add"), int(data.get("port"))
        elif config.startswith("ss://"):
            content = config.replace("ss://", "")
            decoded = content if "@" in content else base64.b64decode(content + "==").decode()
            match = re.search(r'@([^:]+):(\d+)', decoded)
            if match: return match.group(1), int(match.group(2))
    except: pass
    return None, None

# ---------------- GEOIP & RENAME ---------------- #
async def get_country_and_rename(session, config, host):
    proto = config.split("://")[0].upper()
    try:
        async with session.get(f"http://ip-api.com/json/{host}?fields=status,countryCode", timeout=3) as resp:
            data = await resp.json()
            cc = data.get("countryCode", "UN") if data.get("status") == "success" else "UN"
    except:
        cc = "UN"
    
    flag = FLAGS.get(cc, "🌐")
    rename_counter[cc] = rename_counter.get(cc, 0) + 1
    name = f"{flag} {cc}{rename_counter[cc]}-{proto.lower()}"
    
    clean_conf = config.split("#")[0]
    return f"{clean_conf}#{name}"

# ---------------- SCANNER ---------------- #
async def check_config(session, semaphore, config):
    if stop_event.is_set(): return

    host, port = parse_host_port(config)
    if not host: return

    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            
            # Çalışıyorsa isimlendir ve listeye ekle
            final_config = await get_country_and_rename(session, config, host)
            working_list.append(final_config)
            
            print(f"BULDUM [{len(working_list)}]: {host}")
            
            if len(working_list) >= MAX_CONFIG:
                stop_event.set()
        except: pass

# ---------------- PCLOUD ---------------- #
async def pcloud_upload(content):
    url = f"{API_BASE}/uploadfile"
    data = aiohttp.FormData()
    data.add_field('auth', PCLOUD_AUTH)
    data.add_field('path', '/')
    data.add_field('filename', 'working_configs.txt')
    data.add_field('nopartial', '1')
    data.add_field('file', content.encode('utf-8'), filename='working_configs.txt')

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data) as resp:
            res = await resp.json()
            print("YUKLEME:", "OK" if res.get("result") == 0 else f"HATA: {res}")

# ---------------- MAIN ---------------- #
async def main():
    async with aiohttp.ClientSession() as session:
        print("Kaynaklar indiriliyor...")
        async with session.get(CONFIG_URL) as resp:
            configs = list(set((await resp.text()).splitlines()))
        
        print(f"Tarama basladi (Hedef: {MAX_CONFIG} canlı config)...")
        semaphore = asyncio.Semaphore(CONCURRENT)
        tasks = [check_config(session, semaphore, c) for c in configs]
        
        await asyncio.gather(*tasks)
        
        if working_list:
            print(f"Toplam {len(working_list)} config yukleniyor.")
            await pcloud_upload("\n".join(working_list))

if __name__ == "__main__":
    asyncio.run(main())
