#!/usr/bin/env python3
"""
GitHub Action Script - Simplified v2.0
- GeoIP KALDIRILDI (gereksiz)
- Mevcut bayrak/emoji kullanımı (🇩🇪, 🔥, vb.)
- Ülke kodu + protokol ekleme (örn: 🇩🇪 DE-vless, 🔥 Best-trojan)
- Akıllı duplicate detection korundu
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
# RENAME - BASİTLEŞTİRİLMİŞ
##################################################

def rename_config_simple(link):
    """
    Basit isimlendirme - sadece mevcut bayrak/emoji + protokol
    Örnekler:
      🇩🇪 DE-vless
      🇺🇸 US-trojan
      🔥 vless
      vless (bayrak yoksa)
    """
    if not ENABLE_RENAME:
        return link
    
    # Protokol al
    proto = link.split("://")[0].lower()
    
    # Fragment (# sonrası) var mı kontrol et
    if '#' not in link:
        # Fragment yok - sadece protokol ekle
        return f"{link}#{proto}"
    
    # Fragment'i ayır
    base_config, fragment = link.rsplit('#', 1)
    fragment = urllib.parse.unquote(fragment)
    
    # Emoji/Bayrak bul (herhangi bir emoji)
    # Ülke bayrakları: 🇦-🇿 (2 karakter)
    # Diğer emojiler: 🔥, 🌐, ⚡, vb.
    emoji_pattern = re.compile(r'([\U0001F1E6-\U0001F1FF]{2}|[\U0001F300-\U0001F9FF])')
    emoji_match = emoji_pattern.search(fragment)
    
    if not emoji_match:
        # Emoji yok - sadece protokol
        return f"{base_config}#{proto}"
    
    flag_emoji = emoji_match.group(1)
    
    # Ülke bayrağı mı yoksa diğer emoji mi?
    if len(flag_emoji) == 2 and '\U0001F1E6' <= flag_emoji[0] <= '\U0001F1FF':
        # Ülke bayrağı - 2 harfli koda çevir
        # Örnek: 🇩🇪 → DE
        code_points = [ord(c) - 0x1F1E6 + ord('A') for c in flag_emoji]
        country_code = ''.join(chr(c) for c in code_points)
        new_name = f"{flag_emoji} {country_code}-{proto}"
    else:
        # Diğer emoji (🔥, 🌐, ⚡, vb.) - direkt kullan
        new_name = f"{flag_emoji} {proto}"
    
    # Aynı isimden varsa numara ekle
    if new_name in rename_counter:
        rename_counter[new_name] += 1
        new_name = f"{new_name}{rename_counter[new_name]}"
    else:
        rename_counter[new_name] = 1
    
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
    print("🚀 GitHub Action - Simple Rename (v2.0)")
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
