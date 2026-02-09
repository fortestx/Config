#!/usr/bin/env python3
"""
GitHub Action Script - Multi-URL to Yandex Disk (FIXED)
Birden fazla link'ten config çeker ve Yandex Disk'e yükler
"""

import os
import sys
import asyncio
import aiohttp
import re

sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar - GitHub Secrets'tan alınır
CONFIG_URLS = os.getenv("CONFIG_URLS")  # Virgülle ayrılmış URL listesi
YANDEX_TOKEN = os.getenv("YANDEX_TOKEN")  # Yandex OAuth token
YANDEX_OUTPUT_FILE = os.getenv("YANDEX_OUTPUT_FILE", "/working_configs.txt")  # Yandex Disk'teki dosya yolu
YANDEX_API_BASE = "https://cloud-api.yandex.net/v1/disk"
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))  # Aynı anda kaç URL çekilsin

def parse_urls(raw_urls):
    """URL listesini çok akıllı bir şekilde parse et"""
    if not raw_urls:
        return []
    
    # Tüm olası ayırıcıları destekle
    urls = []
    
    # Önce satır satır ayır
    lines = raw_urls.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):  # Boş satır veya yorum
            continue
        
        # Virgül veya noktalı virgül ile ayrılmış URL'ler
        if ',' in line or ';' in line:
            # Her iki ayırıcıyı da destekle
            parts = re.split('[,;]', line)
            for part in parts:
                url = part.strip()
                if url and (url.startswith('http://') or url.startswith('https://')):
                    urls.append(url)
        else:
            # Tek URL
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)
    
    # Duplikaları temizle ama sırayı koru
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
            
            # Content-Type kontrolü (debugging için)
            content_type = resp.headers.get('Content-Type', '')
            print(f"[-] [{url_index}/{total_urls}] Content-Type: {content_type}")
            
            raw_data = await resp.text()
            
            # Config satırlarını bul (protocol:// içeren satırlar)
            configs = []
            for line in raw_data.splitlines():
                line = line.strip()
                if line and "://" in line:
                    # Sadece bilinen protokolleri kabul et
                    if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://']):
                        configs.append(line)
            
            print(f"[+] [{url_index}/{total_urls}] ✅ {len(configs)} config bulundu")
            
            if len(configs) == 0:
                print(f"[!] [{url_index}/{total_urls}] ⚠️ Hiç config bulunamadı - içerik ilk 200 karakter:")
                print(f"    {raw_data[:200]}")
            
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
    
    # URL'leri parse et
    url_list = parse_urls(CONFIG_URLS)
    
    if not url_list:
        print("[!] HATA: Geçerli URL bulunamadı!")
        print(f"[!] Girdi: {CONFIG_URLS[:200]}")
        return None
    
    print("=" * 70)
    print(f"📋 Toplam {len(url_list)} URL bulundu")
    print("=" * 70)
    
    for i, url in enumerate(url_list, 1):
        print(f"  {i}. {url}")
    
    print("=" * 70)
    
    all_configs = []
    
    # Connector ile connection pool ayarla
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, limit_per_host=2)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        # Tüm URL'leri paralel olarak çek (ama sınırlı sayıda)
        tasks = [
            fetch_configs_from_url(session, url, i+1, len(url_list)) 
            for i, url in enumerate(url_list)
        ]
        
        # Semaphore ile eşzamanlı istek sayısını sınırla
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
        async def limited_fetch(task):
            async with semaphore:
                return await task
        
        results = await asyncio.gather(*[limited_fetch(task) for task in tasks], return_exceptions=True)
        
        # Sonuçları topla ve hataları logla
        for i, result in enumerate(results, 1):
            if isinstance(result, Exception):
                print(f"[!] [{i}/{len(url_list)}] ❌ Task hatası: {result}")
            elif isinstance(result, list):
                all_configs.extend(result)
    
    # Duplikaları kaldır (hem link olarak hem de normalize edilmiş haliyle)
    unique_configs = list(dict.fromkeys(all_configs))  # Sırayı koruyarak duplike temizleme
    
    print("=" * 70)
    print(f"[+] Toplam çekilen: {len(all_configs)} config")
    print(f"[+] Benzersiz: {len(unique_configs)} config")
    if len(all_configs) > len(unique_configs):
        print(f"[+] Duplikat: {len(all_configs) - len(unique_configs)} config temizlendi")
    print("=" * 70)
    
    return unique_configs

async def yandex_disk_upload(content):
    """Yandex Disk'e dosya yükle"""
    if not YANDEX_TOKEN:
        print("[!] HATA: YANDEX_TOKEN tanımlanmamış!")
        return False
    
    try:
        headers = {"Authorization": f"OAuth {YANDEX_TOKEN}"}
        
        async with aiohttp.ClientSession() as session:
            # 1. Upload URL'ini al
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
            
            # 2. Dosyayı yükle
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

async def main():
    """Ana program akışı"""
    print("=" * 70)
    print("🚀 GitHub Action - Multi-URL to Yandex Disk (FIXED VERSION)")
    print("=" * 70)
    
    # Environment variables kontrolü
    if not CONFIG_URLS or not YANDEX_TOKEN:
        print("[!] HATA: CONFIG_URLS veya YANDEX_TOKEN secrets eksik!")
        print("")
        print("GitHub > Settings > Secrets and variables > Actions")
        print("")
        print("📝 CONFIG_URLS formatı (desteklenen tüm formatlar):")
        print("  • Tek URL:")
        print("    https://example.com/configs.txt")
        print("")
        print("  • Virgülle ayrılmış:")
        print("    https://url1.com,https://url2.com,https://url3.com")
        print("")
        print("  • Satır satır:")
        print("    https://url1.com")
        print("    https://url2.com")
        print("    https://url3.com")
        print("")
        print("  • Karışık (yorum satırları desteklenir):")
        print("    # Bu bir yorum")
        print("    https://url1.com")
        print("    https://url2.com,https://url3.com")
        print("")
        print("🔑 YANDEX_TOKEN:")
        print("  Yandex OAuth token gerekli")
        print("  https://oauth.yandex.com/authorize?response_type=token&client_id=YOUR_APP_ID")
        sys.exit(1)
    
    # 1. Tüm URL'lerden configleri çek
    configs = await fetch_all_configs()
    
    if not configs:
        print("[!] ❌ Hiçbir config bulunamadı veya çekilemedi")
        sys.exit(1)
    
    # 2. Yandex Disk'e yükle
    content = "\n".join(configs)
    success = await yandex_disk_upload(content)
    
    if success:
        print("=" * 70)
        print(f"[+] ✅ İşlem tamamlandı: {len(configs)} config yüklendi")
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
