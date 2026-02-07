import aiohttp
import asyncio
import base64
import json
import re
import os

# --- AYARLAR ---
URL_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt"
]

PCLOUD_USER = os.environ.get("PCLOUD_USERNAME")
PCLOUD_PASS = os.environ.get("PCLOUD_PASSWORD")
FILE_NAME = "All_configs.txt"
MAX_WORKING = 2000 
TIMEOUT = 3 

working_proxies = []

def decode_base64(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def parse_vmess(vmess_url):
    try:
        b64 = vmess_url.replace("vmess://", "")
        config = json.loads(decode_base64(b64))
        return config.get("add"), int(config.get("port"))
    except: return None, None

def parse_vless_trojan(url):
    try:
        # vless://... @ip:port veya trojan://... @ip:port
        match = re.search(r"@([^:]+):(\d+)", url)
        if match: return match.group(1), int(match.group(2))
        return None, None
    except: return None, None

def parse_ss(url):
    try:
        # ss://base64@ip:port#tag formatı için
        if "@" in url:
            part = url.split("@")[1].split("#")[0]
            ip = part.split(":")[0]
            port = int(part.split(":")[1])
            return ip, port
        return None, None
    except: return None, None

async def check_port(session, proxy, ip, port):
    if len(working_proxies) >= MAX_WORKING: return
    try:
        # TCP Port kontrolü
        conn = asyncio.open_connection(ip, port)
        await asyncio.wait_for(conn, timeout=TIMEOUT)
        working_proxies.append(proxy)
    except: pass

async def fetch_and_scan():
    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        raw_configs = set()
        print("[-] Veriler toplaniyor (Vmess, Vless, Trojan, SS)...")
        for source in URL_SOURCES:
            try:
                async with session.get(source) as resp:
                    text = await resp.text()
                    lines = text.splitlines()
                    for line in lines:
                        line = line.strip()
                        # SS desteği eklendi
                        if line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
                            raw_configs.add(line)
            except: continue

        print(f"[-] {len(raw_configs)} benzersiz config bulundu. Hizli tarama basliyor...")
        tasks = []
        for config in raw_configs:
            if len(working_proxies) >= MAX_WORKING: break
            
            ip, port = None, None
            if config.startswith("vmess://"):
                ip, port = parse_vmess(config)
            elif config.startswith("ss://"):
                ip, port = parse_ss(config)
            else: # vless veya trojan
                ip, port = parse_vless_trojan(config)
            
            if ip and port: 
                tasks.append(check_port(session, config, ip, port))
        
        # 100'erli gruplar halinde paralel tarama
        for i in range(0, len(tasks), 100):
            if len(working_proxies) >= MAX_WORKING: break
            await asyncio.gather(*tasks[i:i+100])

async def upload_to_pcloud():
    if not working_proxies: 
        print("[!] Yuklenecek calisan config bulunamadi.")
        return
        
    content = "\n".join(working_proxies)
    async with aiohttp.ClientSession() as session:
        # 1. Login
        login_url = f"https://api.pcloud.com/userinfo?getauth=1&logout=1&username={PCLOUD_USER}&password={PCLOUD_PASS}"
        async with session.get(login_url) as r:
            res_data = await r.json()
            auth = res_data.get("auth")
            if not auth: 
                print("[!] pCloud Login hatasi! Kullanici adi veya sifreyi kontrol et.")
                return

        # 2. Upload (Dosya varsa üzerine yazar)
        payload = aiohttp.FormData()
        payload.add_field('auth', auth)
        payload.add_field('path', '/')
        payload.add_field('file', content.encode('utf-8'), filename=FILE_NAME)
        
        async with session.post("https://api.pcloud.com/uploadfile", data=payload) as up_r:
            if up_r.status == 200: 
                print(f"[+] BASARILI: {len(working_proxies)} config pCloud'a yuklendi.")
            else: 
                print(f"[!] Yukleme sirasinda hata: {up_r.status}")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(fetch_and_scan())
    loop.run_until_complete(upload_to_pcloud())
