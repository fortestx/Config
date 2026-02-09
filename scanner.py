#!/usr/bin/env python3
"""
GitHub Action Script - Multi-URL Versiyon
Birden fazla link'ten config çeker ve hepsini pCloud'a yükler
"""

import os
import sys
import asyncio
import aiohttp

sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar - GitHub Secrets'tan alınır
CONFIG_URLS = os.getenv("CONFIG_URLS")  # Virgülle ayrılmış URL listesi
PCLOUD_AUTH = os.getenv("PCLOUD_AUTH")
API_BASE = "https://eapi.pcloud.com"

async def fetch_configs_from_url(session, url, url_index):
    """Tek bir URL'den configleri çek"""
    try:
        print(f"[-] [{url_index}] URL çekiliyor: {url}")
        
        async with session.get(url.strip(), timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"[!] [{url_index}] HTTP Hatası: {resp.status}")
                return []
            
            raw_data = await resp.text()
            configs = [line.strip() for line in raw_data.splitlines() if line.strip() and "://" in line]
            
            print(f"[+] [{url_index}] {len(configs)} config bulundu")
            return configs
    
    except asyncio.TimeoutError:
        print(f"[!] [{url_index}] Timeout: {url}")
        return []
    except Exception as e:
        print(f"[!] [{url_index}] Hata: {e}")
        return []

async def fetch_all_configs():
    """Tüm URL'lerden configleri çek"""
    if not CONFIG_URLS:
        print("[!] HATA: CONFIG_URLS tanımlanmamış!")
        return None
    
    # URL listesini ayır (virgül, noktalı virgül veya satır sonu ile)
    url_list = []
    for separator in [',', ';', '\n']:
        if separator in CONFIG_URLS:
            url_list = [u.strip() for u in CONFIG_URLS.split(separator) if u.strip()]
            break
    
    # Eğer ayırıcı yoksa tek URL olarak kabul et
    if not url_list:
        url_list = [CONFIG_URLS.strip()]
    
    print("=" * 60)
    print(f"📋 Toplam {len(url_list)} URL bulundu")
    print("=" * 60)
    
    all_configs = []
    
    async with aiohttp.ClientSession() as session:
        # Tüm URL'leri paralel olarak çek
        tasks = [fetch_configs_from_url(session, url, i+1) for i, url in enumerate(url_list)]
        results = await asyncio.gather(*tasks)
        
        # Tüm sonuçları birleştir
        for configs in results:
            all_configs.extend(configs)
    
    # Duplikaları kaldır
    unique_configs = list(set(all_configs))
    
    print("=" * 60)
    print(f"[+] Toplam: {len(all_configs)} config")
    print(f"[+] Benzersiz: {len(unique_configs)} config")
    print(f"[+] Duplikat: {len(all_configs) - len(unique_configs)} config temizlendi")
    print("=" * 60)
    
    return unique_configs

async def pcloud_upload(content, filename="working_configs.txt"):
    """pCloud'a dosya yükle"""
    if not PCLOUD_AUTH:
        print("[!] HATA: PCLOUD_AUTH tanımlanmamış!")
        return False
    
    try:
        url = f"{API_BASE}/uploadfile"
        data = aiohttp.FormData()
        data.add_field('auth', str(PCLOUD_AUTH))
        data.add_field('path', '/')
        data.add_field('filename', filename)
        data.add_field('nopartial', '1')
        data.add_field('overwrite', '1')
        data.add_field('file', content.encode('utf-8'), filename=filename)
        
        print(f"[-] pCloud'a yükleniyor: {filename}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                res = await resp.json()
                
                if res.get("result") == 0:
                    print(f"[+] ✅ Başarılı: {filename} pCloud'a yüklendi")
                    print(f"[+] 📊 Dosya boyutu: {len(content)} byte")
                    return True
                else:
                    print(f"[!] ❌ pCloud Hatası: {res.get('error', 'Bilinmeyen hata')}")
                    return False
    
    except Exception as e:
        print(f"[!] Upload hatası: {e}")
        return False

async def main():
    """Ana program akışı"""
    print("=" * 60)
    print("GitHub Action - Multi-URL Config Uploader")
    print("=" * 60)
    
    # Environment variables kontrolü
    if not CONFIG_URLS or not PCLOUD_AUTH:
        print("[!] HATA: CONFIG_URLS veya PCLOUD_AUTH secrets eksik!")
        print("    GitHub > Settings > Secrets and variables > Actions")
        print("")
        print("CONFIG_URLS formatı:")
        print("  Tek URL: https://example.com/configs.txt")
        print("  Çoklu URL (virgül): https://url1.com,https://url2.com,https://url3.com")
        print("  Çoklu URL (satır): ")
        print("    https://url1.com")
        print("    https://url2.com")
        sys.exit(1)
    
    # 1. Tüm URL'lerden configleri çek
    configs = await fetch_all_configs()
    
    if not configs:
        print("[!] Hiçbir config bulunamadı veya çekilemedi")
        sys.exit(1)
    
    # 2. pCloud'a yükle
    content = "\n".join(configs)
    success = await pcloud_upload(content, "working_configs.txt")
    
    if success:
        print("=" * 60)
        print(f"[+] ✅ İşlem tamamlandı: {len(configs)} config yüklendi")
        print("=" * 60)
        sys.exit(0)
    else:
        print("[!] ❌ Yükleme başarısız!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
