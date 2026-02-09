#!/usr/bin/env python3
"""
GitHub Action Script - Multi-URL to Yandex Disk with Renaming
Birden fazla link'ten config çeker, önce yerel GeoIP veritabanından,
bulamazsa API'den ülke kodunu alır ve Yandex Disk'e yükler.
"""

import os
import sys
import asyncio
import aiohttp
import re
import json
import base64
import random
import geoip2.database  # EKLENDİ: Veritabanı kütüphanesi

sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar - GitHub Secrets'tan alınır
CONFIG_URLS = os.getenv("CONFIG_URLS")  # Virgülle ayrılmış URL listesi
YANDEX_TOKEN = os.getenv("YANDEX_TOKEN")  # Yandex OAuth token
YANDEX_OUTPUT_FILE = os.getenv("YANDEX_OUTPUT_FILE", "/working_configs.txt")  # Yandex Disk'teki dosya yolu
YANDEX_API_BASE = "https://cloud-api.yandex.net/v1/disk"
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
ENABLE_RENAME = os.getenv("ENABLE_RENAME", "true").lower() == "true"  # İsimlendirme aktif mi
GEOIP_TIMEOUT = int(os.getenv("GEOIP_TIMEOUT", "1"))  # GeoIP timeout
GEOIP_MAX_RETRIES = int(os.getenv("GEOIP_MAX_RETRIES", "1"))  # GeoIP retry sayısı

# GeoIP Veritabanını Yükle (Global)
# GitHub Actions workflow ile indirilen 'GeoLite2-Country.mmdb' dosyasını arar.
DB_PATH = "GeoLite2-Country.mmdb"
geo_reader = None

try:
    geo_reader = geoip2.database.Reader(DB_PATH)
    print(f"[+] GeoIP Veritabanı yüklendi: {DB_PATH}")
except FileNotFoundError:
    print(f"[!] UYARI: {DB_PATH} bulunamadı! Sadece API kullanılacak.")
except Exception as e:
    print(f"[!] Veritabanı hatası: {e}. Sadece API kullanılacak.")

# API için Eş Zamanlı İstek Sınırlayıcı
geoip_sem = asyncio.Semaphore(5) 

# Ülke Kodu Dönüşüm Tablosu (2 harfli → 3 harfli)
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
    "NZ": "NZL", "UA": "UKR", "HU": "HU", "SK": "SVK", "BG": "BGR"
}

# Ülke Bayrak Sözlüğü
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

# İsim sayaçları
rename_counter = {}

##################################################
# İSİMLENDİRME FONKSİYONLARI
##################################################

def safe_b64_decode(s):
    """Base64 decode işlemi - hata toleranslı"""
    try:
        s = s.strip().replace("-", "+").replace("_", "/")
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def extract_host_from_link(link):
    """Link'ten host bilgisini çıkarır"""
    try:
        if link.startswith(("vless://", "trojan://")):
            match = re.search(r'@([^:]+):(\d+)', link)
            if match:
                return match.group(1)
        elif link.startswith("vmess://"):
            data = json.loads(safe_b64_decode(link.replace("vmess://", "")))
            return data.get("add")
        elif link.startswith("ss://"):
            content = link.replace("ss://", "")
            if "@" in content:
                decoded = safe_b64_decode(content.split("@")[0])
                if decoded and "@" in content:
                    match = re.search(r'@([^:]+):(\d+)', content)
                    if match:
                        return match.group(1)
            else:
                decoded = safe_b64_decode(content)
                match = re.search(r'@([^:]+):(\d+)', decoded)
                if match:
                    return match.group(1)
    except:
        pass
    return None

async def get_country_code(session, host, retry=0):
    """Host için ülke kodu al - ÖNCE VERİTABANI, SONRA API"""
    if not host:
        return "UN"

    # --- 1. AŞAMA: OFFLINE VERİTABANI KONTROLÜ ---
    if geo_reader:
        try:
            # geoip2 sadece IP adreslerini kabul eder. 
            # Eğer host bir domain ise (örn: google.com) hata verir, API'ye düşeriz.
            response = geo_reader.country(host)
            cc = response.country.iso_code
            if cc:
                # print(f"[+] GeoIP (DB): {host} → {cc}")
                return cc
        except (ValueError, geoip2.errors.AddressNotFoundError):
            # Host IP değilse veya DB'de yoksa sessizce geç
            pass
        except Exception:
            pass

    # --- 2. AŞAMA: ONLINE API KONTROLÜ (Yedek Plan) ---
    # Eğer veritabanında bulunamadıysa buraya düşer.
    
    # API'nin banlamaması için rastgele küçük bir gecikme
    await asyncio.sleep(random.uniform(0.1, 0.5))

    try:
        async with geoip_sem:
            async with session.get(
                f"http://ip-api.com/json/{host}?fields=status,countryCode",
                timeout=aiohttp.ClientTimeout(total=GEOIP_TIMEOUT)
            ) as resp:
                
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        cc = data.get("countryCode", "UN")
                        if cc != "UN":
                            print(f"[+] GeoIP (API): {host} → {cc}")
                        return cc
                    return "UN"

                elif resp.status == 429: # Rate Limit
                    if retry < GEOIP_MAX_RETRIES:
                        wait_time = (retry + 2) * 2
                        print(f"[!] API LİMİTİ (429): {host} için {wait_time}sn bekleniyor...")
                        await asyncio.sleep(wait_time)
                        return await get_country_code(session, host, retry + 1)

                else:
                    if retry < GEOIP_MAX_RETRIES:
                        await asyncio.sleep(1)
                        return await get_country_code(session, host, retry + 1)

    except (asyncio.TimeoutError, aiohttp.ClientError):
        if retry < GEOIP_MAX_RETRIES:
            await asyncio.sleep(1)
            return await get_country_code(session, host, retry + 1)
    except Exception:
        pass

    return "UN"

async def rename_config(session, link):
    """Config linkini ülke koduna göre yeniden isimlendir"""
    if not ENABLE_RENAME:
        return link
    
    host = extract_host_from_link(link)
    if not host:
        return link
    
    proto = link.split("://")[0].lower()
    
    # Ülke kodunu al
    cc_2letter = await get_country_code(session, host)
    
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
                print(f"[!] [{url_index}/{total_urls}] ❌ HTTP Hatası {resp.status}: {url}")
                return []
            
            raw_data = await resp.text()
            
            configs = []
            for line in raw_data.splitlines():
                line = line.strip()
                if line and "://" in line:
                    if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://']):
                        configs.append(line)
            
            print(f"[+] [{url_index}/{total_urls}] ✅ {len(configs)} config bulundu")
            return configs
    
    except asyncio.TimeoutError:
        print(f"[!] [{url_index}/{total_urls}] ⏱️ Timeout: {url}")
        return []
    except aiohttp.ClientError as e:
        print(f"[!] [{url_index}/{total_urls}] 🌐 Bağlantı hatası: {e}")
        return []
    except Exception as e:
        print(f"[!] [{url_index}/{total_urls}] ❌ Beklenmeyen hata: {e}")
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
    print(f"[+] Benzersiz: {len(unique_configs)} config")
    if len(all_configs) > len(unique_configs):
        print(f"[+] Duplikat: {len(all_configs) - len(unique_configs)} config temizlendi")
    print("=" * 70)
    
    return unique_configs

##################################################
# İSİMLENDİRME VE YÜKLEME
##################################################

async def rename_all_configs(configs):
    """Tüm configleri isimlendirme"""
    if not ENABLE_RENAME or not configs:
        return configs
    
    print("=" * 70)
    print(f"🏷️ İsimlendirme başlatılıyor ({len(configs)} config)...")
    print("=" * 70)
    
    connector = aiohttp.TCPConnector(limit=10, limit_per_host=3)
    async with aiohttp.ClientSession(connector=connector) as session:
        batch_size = 20
        renamed_configs = []
        
        for i in range(0, len(configs), batch_size):
            batch = configs[i:i+batch_size]
            print(f"[-] İlerleme: {min(i+batch_size, len(configs))}/{len(configs)}")
            
            batch_renamed = await asyncio.gather(*[rename_config(session, link) for link in batch])
            renamed_configs.extend(batch_renamed)
            
            # Rate limit için ufak bir bekleme (veritabanı varsa çok şart değil ama güvenli)
            if i + batch_size < len(configs):
                await asyncio.sleep(0.5)
    
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

async def yandex_disk_upload(content):
    """Yandex Disk'e dosya yükle"""
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
                    error_text = await resp.text()
                    print(f"[!] Yanıt: {error_text}")
                    return False
                
                data = await resp.json()
                upload_url = data.get("href")
                
                if not upload_url:
                    print("[!] ❌ Upload URL alınamadı")
                    return False
            
            async with session.put(
                upload_url,
                data=content.encode('utf-8'),
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status in [201, 202]:
                    print(f"[+] ✅ Başarılı: {YANDEX_OUTPUT_FILE} Yandex Disk'e yüklendi")
                    print(f"[+] 📊 Dosya boyutu: {len(content)} byte ({len(content.splitlines())} satır)")
                    return True
                else:
                    print(f"[!] ❌ Yandex upload hatası: {resp.status}")
                    error_text = await resp.text()
                    print(f"[!] Yanıt: {error_text}")
                    return False
    
    except Exception as e:
        print(f"[!] Upload hatası: {e}")
        import traceback
        traceback.print_exc()
        return False

##################################################
# MAIN
##################################################

async def main():
    """Ana program akışı"""
    print("=" * 70)
    print("🚀 GitHub Action - Multi-URL with Renaming (Hybrid GeoIP)")
    print("=" * 70)
    
    if not CONFIG_URLS or not YANDEX_TOKEN:
        print("[!] HATA: CONFIG_URLS veya YANDEX_TOKEN secrets eksik!")
        sys.exit(1)
    
    configs = await fetch_all_configs()
    
    if not configs:
        print("[!] ❌ Hiçbir config bulunamadı veya çekilemedi")
        sys.exit(1)
    
    renamed_configs = await rename_all_configs(configs)
    
    content = "\n".join(renamed_configs)
    success = await yandex_disk_upload(content)
    
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
        print("\n[!] ⚠️ Kullanıcı tarafından durduruldu")
        sys.exit(130)
    except Exception as e:
        print(f"[!] ❌ Fatal hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
