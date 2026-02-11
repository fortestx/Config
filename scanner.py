#!/usr/bin/env python3
"""
GitHub Action Script - Simplified v2.1
- GeoIP KALDIRILDI (gereksiz)
- Mevcut bayrak/emoji kullanımı (🇩🇪, 🔥, vb.)
- Ülke kodu + protokol ekleme (örn: 🇩🇪 DE-vless, 🔥 Best-trojan)
- Akıllı duplicate detection korundu
- FIX: vmess base64 configlerde ps alanından emoji/isim çekme eklendi
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
    try:
        s = s.strip().replace("-", "+").replace("_", "/")
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except:
        return ""

def generate_config_hash(link):
    """
    Config'in benzersiz hash'ini oluştur (duplicate detection için)
    Host, port, uuid/password kombinasyonuna göre
    """
    try:
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
            base = link.split("#")[0]
            return hashlib.md5(base.encode()).hexdigest()
        
        elif link.startswith("ssr://"):
            base = link.split("#")[0]
            return hashlib.md5(base.encode()).hexdigest()
        
        elif link.startswith("hysteria://"):
            parsed = urllib.parse.urlparse(link)
            host = parsed.hostname
            port = parsed.port or 443
            return hashlib.md5(f"hysteria:{host}:{port}".encode()).hexdigest()
        
        else:
            base = link.split("#")[0]
            return hashlib.md5(base.encode()).hexdigest()
    
    except:
        return hashlib.md5(link.encode()).hexdigest()

##################################################
# RENAME - BASİTLEŞTİRİLMİŞ + VMESS FIX
##################################################

def rename_config_simple(link):
    """
    Basit isimlendirme - SADECE bayrak + ülke kodu + protokol (BOŞLUKSUZ)
    
    Giriş:  vless://...#🇯🇵 Tokyo Server Fast 123
    Çıkış:  vless://...#🇯🇵JAP-vless1
    
    Giriş:  trojan://...#🔥 Best Server
    Çıkış:  trojan://...#🔥trojan1
    
    Giriş:  vmess://base64 (ps alanında 🇺🇸 USA Server)
    Çıkış:  vmess://base64_with_updated_ps (🇺🇸USA-vmess1)
    """
    if not ENABLE_RENAME:
        return link
    
    # Protokol al
    proto = link.split("://")[0].lower()
    
    # Config base'i ve fragment'i al
    if '#' in link:
        base_config = link.split('#')[0]
        fragment = link.split('#', 1)[1]
    else:
        base_config = link
        fragment = ""
    
    # vmess base64 ise ps alanından emoji çekmeyi dene
    vmess_data = None
    if proto == "vmess" and not fragment:
        try:
            decoded = safe_b64_decode(link.replace("vmess://", ""))
            if decoded:
                vmess_data = json.loads(decoded)
                ps = vmess_data.get("ps", "")
                if ps:
                    fragment = ps
        except:
            pass
    
    # Emoji/Bayrak bul
    emoji_pattern = re.compile(r'([\U0001F1E6-\U0001F1FF]{2}|[\U0001F300-\U0001F9FF])')
    emoji_match = emoji_pattern.search(fragment)
    
    if not emoji_match:
        # Bayrak yok - sadece protokol + numara
        key = proto
        if key not in rename_counter:
            rename_counter[key] = 0
        rename_counter[key] += 1
        new_name = f"{proto}{rename_counter[key]}"
        
        # vmess için base64 içindeki ps'i güncelle
        if proto == "vmess" and vmess_data is not None:
            try:
                vmess_data["ps"] = new_name
                new_json = json.dumps(vmess_data, separators=(',', ':'), ensure_ascii=False)
                new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
                return f"vmess://{new_b64}"
            except:
                pass
        
        return f"{base_config}#{new_name}"
    
    # Bayrak var
    flag_emoji = emoji_match.group(1)
    
    # Ülke bayrağı mı?
    if len(flag_emoji) == 2 and '\U0001F1E6' <= flag_emoji[0] <= '\U0001F1FF':
        # Ülke bayrağı → Koda çevir
        code_points = [ord(c) - 0x1F1E6 + ord('A') for c in flag_emoji]
        country_code = ''.join(chr(c) for c in code_points)
        
        # Örnek: 🇯🇵 → JP → JAP
        country_map = {
            "JP": "JAP", "US": "USA", "DE": "GER", "GB": "GBR", "FR": "FRA",
            "TR": "TUR", "NL": "NLD", "SG": "SGP", "CA": "CAN", "HK": "HKG",
            "IT": "ITA", "ES": "ESP", "RU": "RUS", "KR": "KOR", "BR": "BRA",
            "AU": "AUS", "IN": "IND", "SE": "SWE", "CH": "CHE", "CN": "CHN",
            "TW": "TWN", "MX": "MEX", "AR": "ARG", "CL": "CHL", "ZA": "ZAF",
            "EG": "EGY", "IL": "ISR", "SA": "SAU", "AE": "ARE", "TH": "THA",
            "VN": "VNM", "ID": "IDN", "MY": "MYS", "PH": "PHL", "NZ": "NZL",
            "UA": "UKR", "HU": "HUN", "SK": "SVK", "BG": "BGR", "PL": "POL",
            "FI": "FIN", "NO": "NOR", "DK": "DNK", "AT": "AUT", "BE": "BEL",
            "CZ": "CZE", "IE": "IRL", "PT": "PRT", "GR": "GRC", "RO": "ROU"
        }
        country_3 = country_map.get(country_code, country_code)
        
        # Key oluştur: bayrak + ülke + protokol
        key = f"{flag_emoji}_{country_3}_{proto}"
        if key not in rename_counter:
            rename_counter[key] = 0
        rename_counter[key] += 1
        
        # BOŞLUKSUZ: 🇯🇵JAP-vless1
        new_name = f"{flag_emoji}{country_3}-{proto}{rename_counter[key]}"
    else:
        # Diğer emoji (🔥, 🌐, vb.)
        key = f"{flag_emoji}_{proto}"
        if key not in rename_counter:
            rename_counter[key] = 0
        rename_counter[key] += 1
        
        # BOŞLUKSUZ: 🔥trojan1
        new_name = f"{flag_emoji}{proto}{rename_counter[key]}"
    
    # vmess için base64 içindeki ps'i güncelle
    if proto == "vmess" and vmess_data is not None:
        try:
            vmess_data["ps"] = new_name
            new_json = json.dumps(vmess_data, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except:
            pass
    
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
            if duplicate_count <= 10:  # İlk 10 duplicate'i göster
                print(f"[!] Duplicate bulundu:")
                print(f"    Orjinal: {seen_hashes[config_hash][:80]}...")
                print(f"    Duplikat: {config[:80]}...")
    
    if duplicate_count > 10:
        print(f"[!] ... ve {duplicate_count - 10} duplicate daha")
    
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
    """Tüm configleri basit isimlendirme ile işle"""
    if not ENABLE_RENAME or not configs:
        return configs
    
    print("=" * 70)
    print(f"🏷️ İsimlendirme başlatılıyor ({len(configs)} config)...")
    print("=" * 70)
    
    renamed_configs = []
    
    for i, link in enumerate(configs, 1):
        renamed = rename_config_simple(link)
        renamed_configs.append(renamed)
        
        if i % 50 == 0:
            print(f"[-] İlerleme: {i}/{len(configs)}")
    
    print("=" * 70)
    print("[+] ✅ İsimlendirme tamamlandı")
    
    # İstatistik göster
    if rename_counter:
        print("=" * 70)
        print("📊 İSİM DAĞILIMI (İlk 20):")
        print("=" * 70)
        sorted_names = sorted(rename_counter.items(), key=lambda x: x[1], reverse=True)
        for name, count in sorted_names[:20]:
            print(f"  {name}: {count} adet")
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
    print("🚀 GitHub Action - Simple Rename (v2.1 - vmess fix)")
    print("=" * 70)
    
    if not CONFIG_URLS or not YANDEX_TOKEN:
        print("[!] HATA: CONFIG_URLS veya YANDEX_TOKEN eksik!")
        sys.exit(1)
    
    # 1. Configleri çek
    configs = await fetch_all_configs()
    
    if not configs:
        print("[!] ❌ Hiçbir config bulunamadı")
        sys.exit(1)
    
    # 2. Akıllı duplicate temizleme
    unique_configs = remove_duplicates(configs)
    
    # 3. Basit isimlendirme
    renamed_configs = rename_all_configs(unique_configs)
    
    # 4. Yandex'e yükle
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
        print("\n[!] ⚠️ Durduruldu")
        sys.exit(130)
    except Exception as e:
        print(f"[!] ❌ Fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
