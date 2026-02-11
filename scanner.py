#!/usr/bin/env python3
"""
GitHub Action Script - Base64 Fix & Smart Rename v2.1
- Base64 abonelikleri otomatik çözülür.
- VMess JSON içindeki (ps) isimleri okunur.
- Akıllı duplicate ve bayrak tespiti.
"""

import os
import sys
import asyncio
import aiohttp
import re
import json
import base64
import hashlib
import urllib.parse

sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar
CONFIG_URLS = os.getenv("CONFIG_URLS")
YANDEX_TOKEN = os.getenv("YANDEX_TOKEN")
YANDEX_OUTPUT_FILE = os.getenv("YANDEX_OUTPUT_FILE", "/working_configs.txt")
YANDEX_API_BASE = "https://cloud-api.yandex.net/v1/disk"
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
ENABLE_RENAME = os.getenv("ENABLE_RENAME", "true").lower() == "true"

rename_counter = {}

##################################################
# PARSER HELPERS
##################################################

def safe_b64_decode(s):
    """Base64 decode - hata toleranslı"""
    if not s: return ""
    try:
        # URL safe karakter düzeltmeleri
        s = s.strip().replace("-", "+").replace("_", "/")
        # Padding ekle
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def generate_config_hash(link):
    """Config'in benzersiz hash'ini oluştur"""
    try:
        if link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username
            host = parsed.hostname
            port = parsed.port or 443
            return hashlib.md5(f"{parsed.scheme}:{uuid}@{host}:{port}".encode()).hexdigest()
        
        elif link.startswith("vmess://"):
            try:
                data = json.loads(safe_b64_decode(link.replace("vmess://", "")))
                uuid = data.get("id", "")
                host = data.get("add", "")
                port = data.get("port", "")
                return hashlib.md5(f"vmess:{uuid}@{host}:{port}".encode()).hexdigest()
            except:
                return hashlib.md5(link.encode()).hexdigest()
        
        else:
            base = link.split("#")[0]
            return hashlib.md5(base.encode()).hexdigest()
    except:
        return hashlib.md5(link.encode()).hexdigest()

##################################################
# RENAME - GÜÇLENDİRİLMİŞ
##################################################

def get_vmess_remark(link):
    """VMess linkinden 'ps' (isim) bilgisini çeker"""
    try:
        b64_part = link.replace("vmess://", "")
        decoded = safe_b64_decode(b64_part)
        data = json.loads(decoded)
        return data.get("ps", "")
    except:
        return ""

def rename_config_simple(link):
    """
    Gelişmiş İsimlendirme:
    1. Önce URL fragment (#sonrası) kontrol edilir.
    2. Yoksa ve VMess ise, JSON decode edilip 'ps' değerine bakılır.
    3. Bayrak bulunur ve yeniden adlandırılır.
    """
    if not ENABLE_RENAME:
        return link
    
    proto = link.split("://")[0].lower()
    base_config = link.split('#')[0]
    
    # İsim/Remark bulma çabası
    original_remark = ""
    if '#' in link:
        original_remark = link.split('#', 1)[1]
    
    # Eğer remark yoksa ve VMess ise, içeriği çözüp bak
    if not original_remark and proto == "vmess":
        original_remark = get_vmess_remark(base_config)
    
    # URL decode yapalım ki %F0%9F gibi emojiler düzelsin
    try:
        original_remark = urllib.parse.unquote(original_remark)
    except:
        pass

    # Emoji/Bayrak bul
    emoji_pattern = re.compile(r'([\U0001F1E6-\U0001F1FF]{2}|[\U0001F300-\U0001F9FF])')
    emoji_match = emoji_pattern.search(original_remark)
    
    new_name = ""
    
    if not emoji_match:
        # Bayrak yok -> sadece protokol + numara
        key = proto
        if key not in rename_counter: rename_counter[key] = 0
        rename_counter[key] += 1
        new_name = f"{proto}{rename_counter[key]}"
    else:
        # Bayrak var
        flag_emoji = emoji_match.group(1)
        
        # Ülke bayrağı mı?
        if len(flag_emoji) == 2 and '\U0001F1E6' <= flag_emoji[0] <= '\U0001F1FF':
            code_points = [ord(c) - 0x1F1E6 + ord('A') for c in flag_emoji]
            country_code = ''.join(chr(c) for c in code_points)
            
            country_map = {
                "JP": "JAP", "US": "USA", "DE": "GER", "GB": "GBR", "FR": "FRA",
                "TR": "TUR", "NL": "NLD", "SG": "SGP", "CA": "CAN", "HK": "HKG",
                "IT": "ITA", "ES": "ESP", "RU": "RUS", "KR": "KOR", "BR": "BRA",
                "AU": "AUS", "IN": "IND", "SE": "SWE", "CH": "CHE", "CN": "CHN",
                "TW": "TWN", "IR": "IRN"
            }
            country_3 = country_map.get(country_code, country_code)
            
            key = f"{flag_emoji}_{country_3}_{proto}"
            if key not in rename_counter: rename_counter[key] = 0
            rename_counter[key] += 1
            
            new_name = f"{flag_emoji}{country_3}-{proto}{rename_counter[key]}"
        else:
            # Diğer emoji
            key = f"{flag_emoji}_{proto}"
            if key not in rename_counter: rename_counter[key] = 0
            rename_counter[key] += 1
            new_name = f"{flag_emoji}{proto}{rename_counter[key]}"
    
    return f"{base_config}#{new_name}"

##################################################
# URL FETCHING - BASE64 DESTEKLİ
##################################################

def parse_urls(raw_urls):
    if not raw_urls: return []
    urls = []
    for line in raw_urls.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('http'): urls.append(line)
    return list(dict.fromkeys(urls)) # Unique

async def fetch_configs_from_url(session, url, url_index, total_urls):
    """
    URL'den config çeker. 
    Eğer içerik Base64 blob ise decode eder.
    """
    try:
        print(f"[-] [{url_index}/{total_urls}] URL çekiliyor: {url}")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        async with session.get(
            url.strip(), 
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=45),
            allow_redirects=True
        ) as resp:
            if resp.status != 200:
                print(f"[!] [{url_index}/{total_urls}] ❌ HTTP {resp.status}")
                return []
            
            raw_data = await resp.text()
            
            # --- BASE64 DETECT & FIX ---
            # Eğer raw_data içinde '://' yoksa, muhtemelen tüm dosya base64 encoded'dır.
            if "://" not in raw_data:
                try:
                    decoded_data = safe_b64_decode(raw_data)
                    # Decode ettikten sonra protokol kontrolü yap
                    if "://" in decoded_data:
                        print(f"[i] [{url_index}/{total_urls}] 🔓 Base64 abonelik çözüldü")
                        raw_data = decoded_data
                except:
                    pass # Decode edilemediyse orjinal kalsın
            # ---------------------------

            configs = []
            supported_protocols = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://', 'hysteria2://', 'tuic://']
            
            for line in raw_data.splitlines():
                line = line.strip()
                if not line: continue
                
                # Eğer satır tek başına bir base64 ise (bazen satır satır base64 olur)
                if "://" not in line and len(line) > 20:
                    try:
                        decoded_line = safe_b64_decode(line)
                        if "://" in decoded_line:
                            line = decoded_line
                    except:
                        pass

                if any(proto in line for proto in supported_protocols):
                    configs.append(line)
            
            print(f"[+] [{url_index}/{total_urls}] ✅ {len(configs)} config bulundu")
            return configs
    
    except Exception as e:
        print(f"[!] [{url_index}/{total_urls}] ❌ Hata: {e}")
        return []

async def fetch_all_configs():
    if not CONFIG_URLS: return None
    url_list = parse_urls(CONFIG_URLS)
    if not url_list: return None
    
    print("=" * 70)
    print(f"📋 {len(url_list)} URL işlenecek")
    
    all_configs = []
    # User-Agent taklidi için session ayarları
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_configs_from_url(session, url, i+1, len(url_list)) for i, url in enumerate(url_list)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_configs.extend(result)
    
    return list(dict.fromkeys(all_configs))

##################################################
# MAIN FLOW
##################################################

def remove_duplicates(configs):
    print("=" * 70)
    print("🔍 Duplicate temizliği...")
    seen = {}
    unique = []
    for c in configs:
        h = generate_config_hash(c)
        if h not in seen:
            seen[h] = c
            unique.append(c)
    print(f"[+] Benzersiz: {len(unique)} / {len(configs)}")
    return unique

async def yandex_disk_upload(content):
    if not YANDEX_TOKEN: return False
    try:
        headers = {"Authorization": f"OAuth {YANDEX_TOKEN}"}
        async with aiohttp.ClientSession() as sess:
            # 1. Get upload link
            async with sess.get(f"{YANDEX_API_BASE}/resources/upload", params={"path": YANDEX_OUTPUT_FILE, "overwrite": "true"}, headers=headers) as resp:
                if resp.status != 200: return False
                href = (await resp.json()).get("href")
            
            # 2. Upload
            async with sess.put(href, data=content.encode('utf-8')) as resp:
                return resp.status in [201, 202]
    except: return False

async def main():
    print("🚀 Script Başlatıldı (v2.1 Fix)")
    if not CONFIG_URLS or not YANDEX_TOKEN:
        print("[!] Token veya URL eksik")
        sys.exit(1)
        
    configs = await fetch_all_configs()
    if not configs:
        print("[!] Config bulunamadı")
        sys.exit(1)
        
    unique = remove_duplicates(configs)
    
    print("=" * 70)
    print("🏷️ İsimlendirme yapılıyor...")
    renamed = [rename_config_simple(c) for c in unique]
    
    content = "\n".join(renamed)
    if await yandex_disk_upload(content):
        print("[+] ✅ Yandex Upload Başarılı!")
    else:
        print("[!] ❌ Upload Başarısız")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
