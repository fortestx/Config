#!/usr/bin/env python3
"""
GitHub Action Script - Basit Versiyon
Link'ten config çeker ve doğrudan pCloud'a yükler
"""

import os
import sys
import asyncio
import aiohttp

sys.stdout.reconfigure(encoding='utf-8')

# Ayarlar - GitHub Secrets'tan alınır
CONFIG_URL = os.getenv("CONFIG_URL")
PCLOUD_AUTH = os.getenv("PCLOUD_AUTH")
API_BASE = "https://eapi.pcloud.com"

async def fetch_configs():
    """Config URL'sinden tüm linkleri çek"""
    if not CONFIG_URL:
        print("[!] HATA: CONFIG_URL tanımlanmamış!")
        return None
    
    try:
        print(f"[-] Configler çekiliyor: {CONFIG_URL}")
        async with aiohttp.ClientSession() as session:
            async with session.get(CONFIG_URL, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    print(f"[!] HTTP Hatası: {resp.status}")
                    return None
                
                raw_data = await resp.text()
                configs = [line.strip() for line in raw_data.splitlines() if line.strip() and "://" in line]
                
                # Duplikaları kaldır
                configs = list(set(configs))
                
                print(f"[+] {len(configs)} benzersiz config bulundu")
                return configs
    
    except asyncio.TimeoutError:
        print("[!] Timeout: Bağlantı zaman aşımına uğradı")
        return None
    except Exception as e:
        print(f"[!] Hata: {e}")
        return None

async def pcloud_upload(content, filename="all_configs.txt"):
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
    print("GitHub Action - Config Uploader")
    print("=" * 60)
    
    # Environment variables kontrolü
    if not CONFIG_URL or not PCLOUD_AUTH:
        print("[!] HATA: CONFIG_URL veya PCLOUD_AUTH secrets eksik!")
        print("    GitHub > Settings > Secrets and variables > Actions")
        sys.exit(1)
    
    # 1. Configleri çek
    configs = await fetch_configs()
    
    if not configs:
        print("[!] Config bulunamadı veya çekilemedi")
        sys.exit(1)
    
    # 2. pCloud'a yükle
    content = "\n".join(configs)
    success = await pcloud_upload(content, "all_configs.txt")
    
    if success:
        print("=" * 60)
        print(f"[+] İşlem tamamlandı: {len(configs)} config yüklendi")
        print("=" * 60)
        sys.exit(0)
    else:
        print("[!] Yükleme başarısız!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
