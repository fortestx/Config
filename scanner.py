#!/usr/bin/env python3
"""
GitHub Action Script - Multi-URL to Yandex Disk with Local GeoIP & Deduplication
- GeoIP database kullanarak rate limit yok
- Akıllı duplicate detection (aynı server/port/uuid farklı isim)
- Geliştirilmiş parser (ssr, hysteria desteği)
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
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

# Ülke Kodu Haritaları
COUNTRY_CODE_MAP = {
    "TR": "TUR", "US": "USA", "DE": "GER", "GB": "GBR", "FR": "FRA",
    "NL": "NLD", "SG": "SGP", "JP": "JPN", "CA": "CAN", "HK": "HKG",
    "IT": "ITA", "ES": "ESP", "RU": "RUS", "KR": "KOR", "BR": "BRA",
    "AU": "AUS", "IN": "IND", "SE": "SWE", "CH": "CHE", "PL": "POL",
    "FI": "FIN", "NO": "NOR", "DK": "DNK", "AT": "AUT", "BE": "BEL",
    "CZ": "CZE", "IE": "IRL", "PT": "PRT", "GR": "GRC", "RO": "ROU",
    "CN": "CHN", "TW": "TWN", "MX": "MEX", "AR": "ARG", "CL": "CHL",
    "ZA": "ZAF", "EG": "EGY", "IL": "ISR", "SA": "SAU", "AE": "ARE",
    "TH": "THA", "VN": "VNM", "ID": "IDN", "MY": "MYS", "PH": "PHL",
    "NZ": "NZL", "UA": "UKR", "HU": "HUN", "SK": "SVK", "BG": "BGR"
}

FLAGS = {
    "TR": "🇹🇷", "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", 
    "NL": "🇳🇱", "SG": "🇸🇬", "JP": "🇯🇵", "CA": "🇨🇦", "HK": "🇭🇰",
    "IT": "🇮🇹", "ES": "🇪🇸", "RU": "🇷🇺", "KR": "🇰🇷", "BR": "🇧🇷",
    "AU": "🇦🇺", "IN": "🇮🇳", "SE": "🇸🇪", "CH": "🇨🇭", "PL": "🇵🇱",
    "FI": "🇫🇮", "NO": "🇳🇴", "DK": "🇩🇰", "AT": "🇦🇹", "BE": "🇧🇪",
    "CZ": "🇨🇿", "IE": "🇮🇪", "PT": "🇵🇹", "GR": "🇬🇷", "RO": "🇷🇴",
    "CN": "🇨🇳", "TW": "🇹🇼", "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱",
    "ZA": "🇿🇦", "EG": "🇪🇬", "IL": "🇮🇱", "SA": "🇸🇦", "AE": "🇦🇪",
    "TH": "🇹🇭", "VN": "🇻🇳", "ID": "🇮🇩", "MY": "🇲🇾", "PH": "🇵🇭",
    "NZ": "🇳🇿", "UA": "🇺🇦", "HU": "🇭🇺", "SK": "🇸🇰", "BG": "🇧🇬"
}

rename_counter = {}
geoip_reader = None

##################################################
# GEOIP DATABASE
##################################################

async def download_geoip_db():
    """GeoIP database'i indir"""
    global geoip_reader
    
    try:
        print("[*] GeoIP database indiriliyor...")
        
        # geoip2 modülünü yükle
        try:
            import geoip2.database
        except ImportError:
            print("[!] geoip2 modülü yüklü değil, pip install yapılıyor...")
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "geoip2", "-q"])
            import geoip2.database
        
        # Database'i indir
        db_path = "/tmp/GeoLite2-Country.mmdb"
        
        if not os.path.exists(db_path):
            async with aiohttp.ClientSession() as session:
                async with session.get(GEOIP_DB_URL, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status == 200:
                        with open(db_path, 'wb') as f:
                            f.write(await resp.read())
                        print(f"[+] GeoIP database indirildi: {db_path}")
                    else:
                        print(f"[!] GeoIP download hatası: {resp.status}")
                        return False
        else:
            print(f"[+] GeoIP database mevcut: {db_path}")
        
        # Reader'ı aç
        geoip_reader = geoip2.database.Reader(db_path)
        print("[+] GeoIP database hazır!")
        return True
    
    except Exception as e:
        print(f"[!] GeoIP database hatası: {e}")
        return False

def get_country_from_ip(ip):
    """IP'den ülke kodunu al (local database ile)"""
    global geoip_reader
    
    if not geoip_reader:
        return "UN"
    
    try:
        response = geoip_reader.country(ip)
        cc = response.country.iso_code
        return cc if cc else "UN"
    except:
        return "UN"

##################################################
# GELİŞTİRİLMİŞ PARSER
##################################################

def safe_b64_decode(s):
    """Base64 decode - hata toleranslı"""
    try:
        s = s.strip().replace("-", "+").replace("_", "/")
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except:
        return ""

def extract_host_from_link(link):
    """Link'ten host bilgisini çıkar - GELİŞTİRİLMİŞ"""
    try:
        # VLESS, Trojan
        if link.startswith(("vless://", "trojan://")):
            match = re.search(r'@([^:/?]+)', link)
            if match:
                return match.group(1)
        
        # VMess
        elif link.startswith("vmess://"):
            data = json.loads(safe_b64_decode(link.replace("vmess://", "")))
            return data.get("add")
        
        # Shadowsocks
        elif link.startswith("ss://"):
            content = link.replace("ss://", "").split("#")[0]
            
            # Format 1: method:password@server:port
            if "@" in content:
                server_part = content.split("@")[1]
                match = re.search(r'^([^:]+)', server_part)
                if match:
                    return match.group(1)
            
            # Format 2: base64(method:password)@server:port
            else:
                decoded = safe_b64_decode(content)
                if "@" in decoded:
                    match = re.search(r'@([^:]+)', decoded)
                    if match:
                        return match.group(1)
        
        # SSR
        elif link.startswith("ssr://"):
            decoded = safe_b64_decode(link.replace("ssr://", ""))
            match = re.search(r'^([^:]+)', decoded)
            if match:
                return match.group(1)
        
        # Hysteria
        elif link.startswith("hysteria://"):
            parsed = urllib.parse.urlparse(link)
            return parsed.hostname
        
    except:
        pass
    
    return None

def generate_config_hash(link):
    """
    Config'in benzersiz hash'ini oluştur (duplicate detection için)
    Host, port, uuid/password kombinasyonuna göre
    """
    try:
        # URL'i parse et
        if link.startswith("vless://"):
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username
            host = parsed.hostname
            port = parsed.port or 443
            return hashlib.md5(f"vless:{uuid}@{host}:{port}".encode()).hexdigest()
        
        elif link.startswith("vmess://"):
            data = json.loads(safe_b64_decode(link.replace("vmess://", "")))
            uuid = data.get("id")
            host = data.get("add")
            port = data.get("port")
            return hashlib.md5(f"vmess:{uuid}@{host}:{port}".encode()).hexdigest()
        
        elif link.startswith("trojan://"):
            parsed = urllib.parse.urlparse(link)
            password = parsed.username
            host = parsed.hostname
            port = parsed.port or 443
            return hashlib.md5(f"trojan:{password}@{host}:{port}".encode()).hexdigest()
        
        elif link.startswith("ss://"):
            # Basitleştirilmiş hash
            base = link.split("#")[0]
            return hashlib.md5(base.encode()).hexdigest()
        
        else:
            # Fallback: tüm link'i hash'le
            base = link.split("#")[0]
            return hashlib.md5(base.encode()).hexdigest()
    
    except:
        # Hata durumunda tüm link
        return hashlib.md5(link.encode()).hexdigest()

def rename_config_local(link):
    """Config'i local GeoIP database ile isimlendir"""
    if not ENABLE_RENAME:
        return link
    
    host = extract_host_from_link(link)
    if not host:
        return link
    
    proto = link.split("://")[0].lower()
    
    # GeoIP ile ülke kodu al
    cc_2letter = get_country_from_ip(host)
    
    # 3 harfli koda çevir
    cc_3letter = COUNTRY_CODE_MAP.get(cc_2letter, "UNK")
    
    # Bayrak al
    flag = FLAGS.get(cc_2letter, "🌐")
    
    # Sayaç
    if cc_3letter not in rename_counter:
        rename_counter[cc_3letter] = 0
    rename_counter[cc_3letter] += 1
    
    new_name = f"{flag} {cc_3letter}{rename_counter[cc_3letter]}-{proto}"
    base_config = link.split("#")[0]
    
    return f"{base_config}#{new_name}"

##################################################
# URL FETCHING
##################################################

def parse_urls(raw_urls):
    """URL listesini parse et"""
    if not raw_urls:
        return []
    
    urls = []
    lines = raw_urls.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if ',' in line or ';' in line:
            parts = re.split('[,;]', line)
            for part in parts:
                url = part.strip()
                if url and (url.startswith('http://') or url.startswith('https://')):
                    urls.append(url)
        else:
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)
    
    # Duplikaları temizle
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls

async def fetch_configs_from_url(session, url, url_index, total_urls):
    """Tek bir URL'den configleri çek"""
    try:
        print(f"[-] [{url_index}/{total_urls}] URL çekiliyor: {url}")
        
        async with session.get(
            url.strip(), 
            timeout=aiohttp.ClientTimeout(total=45),
            allow_redirects=True
        ) as resp:
            if resp.status != 200:
                print(f"[!] [{url_index}/{total_urls}] ❌ HTTP {resp.status}: {url}")
                return []
            
            raw_data = await resp.text()
            
            # Tüm proxy protokollerini destekle
            configs = []
            supported_protocols = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://']
            
            for line in raw_data.splitlines():
                line = line.strip()
                if line and "://" in line:
                    if any(proto in line for proto in supported_protocols):
                        configs.append(line)
            
            print(f"[+] [{url_index}/{total_urls}] ✅ {len(configs)} config bulundu")
            return configs
    
    except Exception as e:
        print(f"[!] [{url_index}/{total_urls}] ❌ Hata: {e}")
        return []

async def fetch_all_configs():
    """Tüm URL'lerden configleri çek"""
    if not CONFIG_URLS:
        print("[!] HATA: CONFIG_URLS tanımlanmamış!")
        return None
    
    url_list = parse_urls(CONFIG_URLS)
    
    if not url_list:
        print("[!] HATA: Geçerli URL bulunamadı!")
        return None
    
    print("=" * 70)
    print(f"📋 Toplam {len(url_list)} URL bulundu")
    print("=" * 70)
    
    for i, url in enumerate(url_list, 1):
        print(f"  {i}. {url}")
    
    print("=" * 70)
    
    all_configs = []
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, limit_per_host=2)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            fetch_configs_from_url(session, url, i+1, len(url_list)) 
            for i, url in enumerate(url_list)
        ]
        
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def limited_fetch(task):
            async with semaphore:
                return await task
        
        results = await asyncio.gather(*[limited_fetch(task) for task in tasks], return_exceptions=True)
        
        for i, result in enumerate(results, 1):
            if isinstance(result, Exception):
                print(f"[!] [{i}/{len(url_list)}] ❌ Task hatası: {result}")
            elif isinstance(result, list):
                all_configs.extend(result)
    
    unique_configs = list(dict.fromkeys(all_configs))
    
    print("=" * 70)
    print(f"[+] Toplam çekilen: {len(all_configs)} config")
    print(f"[+] Benzersiz (basit): {len(unique_configs)} config")
    if len(all_configs) > len(unique_configs):
        print(f"[+] Basit duplikat: {len(all_configs) - len(unique_configs)} temizlendi")
    print("=" * 70)
    
    return unique_configs

##################################################
# DUPLICATE DETECTION
##################################################

def remove_duplicates(configs):
    """
    Akıllı duplicate temizleme
    Aynı server/port/uuid olan configleri temizle (isim farklı olsa bile)
    """
    print("=" * 70)
    print("🔍 Akıllı duplicate detection başlatılıyor...")
    print("=" * 70)
    
    seen_hashes = {}
    unique_configs = []
    duplicate_count = 0
    
    for config in configs:
        config_hash = generate_config_hash(config)
        
        if config_hash not in seen_hashes:
            seen_hashes[config_hash] = config
            unique_configs.append(config)
        else:
            duplicate_count += 1
            print(f"[!] Duplicate bulundu:")
            print(f"    Orjinal: {seen_hashes[config_hash][:80]}...")
            print(f"    Duplikat: {config[:80]}...")
    
    print("=" * 70)
    print(f"[+] Akıllı temizleme tamamlandı")
    print(f"[+] Benzersiz config: {len(unique_configs)}")
    print(f"[+] Duplicate temizlendi: {duplicate_count}")
    print("=" * 70)
    
    return unique_configs

##################################################
# İSİMLENDİRME
##################################################

def rename_all_configs(configs):
    """Tüm configleri isimlendir (senkron - çünkü local database)"""
    if not ENABLE_RENAME or not configs:
        return configs
    
    print("=" * 70)
    print(f"🏷️ İsimlendirme başlatılıyor ({len(configs)} config)...")
    print("=" * 70)
    
    renamed_configs = []
    
    for i, link in enumerate(configs, 1):
        renamed = rename_config_local(link)
        renamed_configs.append(renamed)
        
        if i % 50 == 0:
            print(f"[-] İlerleme: {i}/{len(configs)}")
    
    print("=" * 70)
    print("[+] ✅ İsimlendirme tamamlandı")
    
    # Ülke dağılımı
    if rename_counter:
        print("=" * 70)
        print("🌍 ÜLKE DAĞILIMI:")
        print("=" * 70)
        sorted_countries = sorted(rename_counter.items(), key=lambda x: x[1], reverse=True)
        for cc_3letter, count in sorted_countries[:15]:
            cc_2letter = None
            for key, val in COUNTRY_CODE_MAP.items():
                if val == cc_3letter:
                    cc_2letter = key
                    break
            
            flag = FLAGS.get(cc_2letter, "🌐") if cc_2letter else "🌐"
            print(f"  {flag} {cc_3letter}: {count} config")
        print("=" * 70)
    
    return renamed_configs

##################################################
# YANDEX UPLOAD
##################################################

async def yandex_disk_upload(content):
    """Yandex Disk'e yükle"""
    if not YANDEX_TOKEN:
        print("[!] HATA: YANDEX_TOKEN tanımlanmamış!")
        return False
    
    try:
        headers = {"Authorization": f"OAuth {YANDEX_TOKEN}"}
        
        async with aiohttp.ClientSession() as session:
            print(f"[-] Yandex Disk'e yükleniyor: {YANDEX_OUTPUT_FILE}")
            
            async with session.get(
                f"{YANDEX_API_BASE}/resources/upload",
                params={"path": YANDEX_OUTPUT_FILE, "overwrite": "true"},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status != 200:
                    print(f"[!] ❌ Yandex API hatası: {resp.status}")
                    return False
                
                data = await resp.json()
                upload_url = data.get("href")
            
            async with session.put(
                upload_url,
                data=content.encode('utf-8'),
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status in [201, 202]:
                    print(f"[+] ✅ Başarılı: {YANDEX_OUTPUT_FILE}")
                    print(f"[+] 📊 {len(content)} byte ({len(content.splitlines())} satır)")
                    return True
                else:
                    print(f"[!] ❌ Upload hatası: {resp.status}")
                    return False
    
    except Exception as e:
        print(f"[!] Upload hatası: {e}")
        return False

##################################################
# MAIN
##################################################

async def main():
    """Ana program"""
    print("=" * 70)
    print("🚀 GitHub Action - GeoIP + Deduplication")
    print("=" * 70)
    
    if not CONFIG_URLS or not YANDEX_TOKEN:
        print("[!] HATA: CONFIG_URLS veya YANDEX_TOKEN eksik!")
        sys.exit(1)
    
    # 1. GeoIP database indir
    if ENABLE_RENAME:
        if not await download_geoip_db():
            print("[!] GeoIP database yüklenemedi, isimlendirme devre dışı")
    
    # 2. Configleri çek
    configs = await fetch_all_configs()
    
    if not configs:
        print("[!] ❌ Hiçbir config bulunamadı")
        sys.exit(1)
    
    # 3. Akıllı duplicate temizleme
    unique_configs = remove_duplicates(configs)
    
    # 4. İsimlendirme (senkron - local database)
    renamed_configs = rename_all_configs(unique_configs)
    
    # 5. Yandex'e yükle
    content = "\n".join(renamed_configs)
    success = await yandex_disk_upload(content)
    
    # 6. GeoIP database temizle
    if geoip_reader:
        geoip_reader.close()
    
    if success:
        print("=" * 70)
        print(f"[+] ✅ İşlem tamamlandı: {len(renamed_configs)} config yüklendi")
        print("=" * 70)
        sys.exit(0)
    else:
        print("[!] ❌ Yükleme başarısız!")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] ⚠️ Durduruldu")
        sys.exit(130)
    except Exception as e:
        print(f"[!] ❌ Fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
