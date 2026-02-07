import os
import sys
import asyncio
import aiohttp
import base64
import json
import re

sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar - GitHub Secrets'tan alınır
CONFIG_URL = os.getenv("CONFIG_URL")
PCLOUD_AUTH = os.getenv("PCLOUD_AUTH")
API_BASE = "https://eapi.pcloud.com"

MAX_CONFIG = 2000
TIMEOUT = 4
CONCURRENT = 350

# Ülke Bayrak Sözlüğü
FLAGS = {
    "TR": "🇹🇷", "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", 
    "NL": "🇳🇱", "SG": "🇸🇬", "JP": "🇯🇵", "CA": "🇨🇦", "HK": "🇭🇰",
    "IT": "🇮🇹", "ES": "🇪🇸", "RU": "🇷🇺", "KR": "🇰🇷", "BR": "🇧🇷"
}

rename_counter = {}
working_list = []

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

async def get_country_and_rename(session, config, host):
    # Protokolü al (vless, vmess vb.)
    proto = config.split("://")[0].lower()
    cc = "UN" # Bilinmeyen ülke için
    
    try:
        async with session.get(f"http://ip-api.com/json/{host}?fields=status,countryCode", timeout=2) as resp:
            data = await resp.json()
            if data.get("status") == "success":
                cc = data.get("countryCode", "UN")
    except: pass
    
    flag = FLAGS.get(cc, "🌐")
    # Her ülke için ayrı sayaç tut
    rename_counter[cc] = rename_counter.get(cc, 0) + 1
    
    # FORMAT: 🇩🇪 DE1-vless
    new_name = f"{flag} {cc}{rename_counter[cc]}-{proto}"
    
    # Eski ismi (varsa # işaretinden sonrasını) tamamen SİL ve yeni ismi ekle
    base_config = config.split("#")[0]
    return f"{base_config}#{new_name}"

async def check_config(session, semaphore, config):
    if len(working_list) >= MAX_CONFIG:
        return None

    host, port = parse_host_port(config)
    if not host: return None

    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            
            # Çalışıyorsa isimlendirmeyi yap
            renamed = await get_country_and_rename(session, config, host)
            return renamed
        except:
            return None

async def pcloud_upload(content):
    if not PCLOUD_AUTH:
        print("[!] Hata: PCLOUD_AUTH boş, yükleme yapılamaz.")
        return

    url = f"{API_BASE}/uploadfile"
    data = aiohttp.FormData()
    data.add_field('auth', str(PCLOUD_AUTH)) # NoneType hatasını önlemek için str() ekledik
    data.add_field('path', '/')
    data.add_field('filename', 'working_configs.txt')
    data.add_field('nopartial', '1')
    data.add_field('file', content.encode('utf-8'), filename='working_configs.txt')

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data) as resp:
            res = await resp.json()
            if res.get("result") == 0:
                print(f"[+] Başarılı: 2000 config pCloud'a yüklendi.")
            else:
                print(f"[!] pCloud Hatası: {res}")

async def main():
    if not CONFIG_URL or not PCLOUD_AUTH:
        print("[!] HATA: Secrets (CONFIG_URL veya PCLOUD_AUTH) eksik!")
        return

    async with aiohttp.ClientSession() as session:
        print("[-] Configler çekiliyor...")
        async with session.get(CONFIG_URL) as resp:
            raw_data = await resp.text()
            configs = list(set(raw_data.splitlines()))
        
        print(f"[-] Tarama başladı... (Hedef: {MAX_CONFIG})")
        semaphore = asyncio.Semaphore(CONCURRENT)
        tasks = [check_config(session, semaphore, c) for c in configs]
        
        for task in asyncio.as_completed(tasks):
            if len(working_list) >= MAX_CONFIG:
                break
            
            result = await task
            if result:
                working_list.append(result)
                if len(working_list) % 50 == 0:
                    print(f"İlerleme: {len(working_list)} canlı bulundu.")

        if working_list:
            await pcloud_upload("\n".join(working_list))
        else:
            print("[!] Çalışan config bulunamadı.")

if __name__ == "__main__":
    asyncio.run(main())
