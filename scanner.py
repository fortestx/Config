#!/usr/bin/env python3
"""
GitHub Action Script - Ultimate Proxy Manager v2.2
- Base64 abonelikleri otomatik çözer.
- VMess JSON içindeki (ps) isimleri ve bayrakları okur.
- Cloudflare engeli için User-Agent eklenmiştir.
- Akıllı duplicate ve bayrak tespiti içerir.
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

# UTF-8 ayarı (Emojiler için kritik)
sys.stdout.reconfigure(encoding='utf-8')

# --- AYARLAR (GitHub Secrets / Env) ---
CONFIG_URLS = os.getenv("CONFIG_URLS")
YANDEX_TOKEN = os.getenv("YANDEX_TOKEN")
YANDEX_OUTPUT_FILE = os.getenv("YANDEX_OUTPUT_FILE", "/working_configs.txt")
YANDEX_API_BASE = "https://cloud-api.yandex.net/v1/disk"
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
ENABLE_RENAME = os.getenv("ENABLE_RENAME", "true").lower() == "true"

rename_counter = {}

##################################################
# YARDIMCI ARAÇLAR (DECODE & HASH)
##################################################

def safe_b64_decode(s):
    """Base64 decode - Padding ve URL-safe hatalarını giderir."""
    if not s: return ""
    try:
        s = s.strip().replace("-", "+").replace("_", "/")
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except:
        return ""

def generate_config_hash(link):
    """Config'in benzersiz kimliğini oluşturur (Duplicate kontrolü)."""
    try:
        # Linkin config kısmını al (# sonrasını at)
        clean_link = link.split('#')[0]
        
        if clean_link.startswith("vmess://"):
            data_raw = safe_b64_decode(clean_link.replace("vmess://", ""))
            data = json.loads(data_raw)
            # Host, port ve id'yi birleştirip hashle
            key = f"vmess:{data.get('add')}:{data.get('port')}:{data.get('id')}"
            return hashlib.md5(key.encode()).hexdigest()
        
        elif "://" in clean_link:
            # Diğer protokoller için (vless, trojan, ss)
            parsed = urllib.parse.urlparse(clean_link)
            key = f"{parsed.scheme}:{parsed.username}@{parsed.hostname}:{parsed.port}"
            return hashlib.md5(key.encode()).hexdigest()
        
        return hashlib.md5(clean_link.encode()).hexdigest()
    except:
        return hashlib.md5(link.encode()).hexdigest()

##################################################
# İSİMLENDİRME VE BAYRAK ANALİZİ
##################################################

def get_vmess_remark(link):
    """VMess linkinin içindeki JSON'dan 'ps' (isim) alanını çeker."""
    try:
        b64_part = re.sub(r'^vmess://', '', link.split('#')[0], flags=re.IGNORECASE).strip()
        decoded = safe_b64_decode(b64_part)
        if decoded:
            data = json.loads(decoded)
            return str(data.get("ps", "")).strip()
    except:
        pass
    return ""

def rename_config_simple(link):
    """Config'i analiz eder ve Bayrak + Ülke Kodu + Protokol olarak yeniden adlandırır."""
    if not ENABLE_RENAME:
        return link
    
    try:
        # Protokolü bul (vless, vmess vb.)
        proto_match = re.match(r'^([^:]+)', link)
        proto = proto_match.group(1).lower() if proto_match else "proxy"
        base_link = link.split('#')[0]
        
        # 1. Aşama: İsim (remark) bulma
        remark = ""
        if '#' in link:
            # URL sonunda etiket varsa al
            remark = link.split('#', 1)[1]
        
        if not remark and proto == "vmess":
            # Etiket yoksa VMess JSON içine bak
            remark = get_vmess_remark(base_link)
        
        # URL Decode (Emoji kodlarını gerçek emojiye çevirir)
        remark = urllib.parse.unquote(remark)

        # 2. Aşama: Emoji/Bayrak tespiti
        emoji_pattern = re.compile(r'([\U0001F1E6-\U0001F1FF]{2}|[\U0001F300-\U0001F9FF])')
        emoji_match = emoji_pattern.search(remark)
        
        if not emoji_match:
            # Bayrak yoksa: vmess1, vless2 vb.
            key = proto
            rename_counter[key] = rename_counter.get(key, 0) + 1
            new_name = f"{proto}{rename_counter[key]}"
        else:
            flag = emoji_match.group(1)
            # Eğer ülke bayrağıysa kodu 3 harfliye çevir (JP -> JAP)
            if len(flag) == 2 and '\U0001F1E6' <= flag[0] <= '\U0001F1FF':
                code_points = [ord(c) - 0x1F1E6 + ord('A') for c in flag]
                c_code = ''.join(chr(c) for c in code_points)
                
                mapping = {
                    "JP": "JAP", "US": "USA", "DE": "GER", "GB": "GBR", "FR": "FRA",
                    "TR": "TUR", "NL": "NLD", "SG": "SGP", "CA": "CAN", "HK": "HKG",
                    "RU": "RUS", "KR": "KOR", "IR": "IRN", "IT": "ITA", "ES": "ESP"
                }
                c_3 = mapping.get(c_code, c_code)
                key = f"{flag}_{c_3}_{proto}"
                rename_counter[key] = rename_counter.get(key, 0) + 1
                new_name = f"{flag}{c_3}-{proto}{rename_counter[key]}"
            else:
                # Diğer emojiler (🔥, 🌐)
                key = f"{flag}_{proto}"
                rename_counter[key] = rename_counter.get(key, 0) + 1
                new_name = f"{flag}{proto}{rename_counter[key]}"
        
        return f"{base_link}#{new_name}"
    except:
        return link

##################################################
# VERİ ÇEKME (HTTP FETCH)
##################################################

async def fetch_configs_from_url(session, url, idx, total):
    """URL'den veriyi çeker, Base64 ise çözer ve configleri ayıklar."""
    try:
        print(f"[-] [{idx}/{total}] Çekiliyor: {url}")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}
        
        async with session.get(url.strip(), headers=headers, timeout=30) as resp:
            if resp.status != 200: return []
            
            text = await resp.text()
            
            # --- OTOMATİK BASE64 ABONELİK ÇÖZÜMÜ ---
            if "://" not in text and len(text.strip()) > 10:
                decoded = safe_b64_decode(text)
                if "://" in decoded:
                    print(f"    [i] Base64 abonelik içeriği çözüldü.")
                    text = decoded
            
            configs = []
            protos = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria', 'tuic://']
            
            for line in text.splitlines():
                line = line.strip()
                if not line: continue
                # Satır bazlı base64 kontrolü
                if "://" not in line and len(line) > 30:
                    try:
                        d_line = safe_b64_decode(line)
                        if "://" in d_line: line = d_line
                    except: pass
                
                if any(p in line for p in protos):
                    configs.append(line)
            
            return configs
    except Exception as e:
        print(f"    [!] Hata: {url} -> {e}")
        return []

##################################################
# ANA DÖNGÜ VE YÜKLEME
##################################################

async def yandex_upload(content):
    if not YANDEX_TOKEN: return False
    headers = {"Authorization": f"OAuth {YANDEX_TOKEN}"}
    try:
        async with aiohttp.ClientSession() as sess:
            # Yükleme linki al
            async with sess.get(f"{YANDEX_API_BASE}/resources/upload", params={"path": YANDEX_OUTPUT_FILE, "overwrite": "true"}, headers=headers) as r:
                if r.status != 200: return False
                url = (await r.json()).get("href")
            # Dosyayı gönder
            async with sess.put(url, data=content.encode('utf-8')) as r:
                return r.status in [201, 202]
    except: return False

async def main():
    print("🚀 GitHub Action - Proxy Sync v2.2 Başlatıldı")
    
    if not CONFIG_URLS:
        print("[!] CONFIG_URLS bulunamadı!"); return

    urls = [u.strip() for u in CONFIG_URLS.split('\n') if u.strip() and not u.startswith('#')]
    all_configs = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_configs_from_url(session, url, i+1, len(urls)) for i, url in enumerate(urls)]
        results = await asyncio.gather(*tasks)
        for r in results: all_configs.extend(r)

    if not all_configs:
        print("[!] Hiç config toplanamadı!"); return

    # 1. Tekilleştirme (Hash tabanlı)
    unique_map = {}
    for c in all_configs:
        h = generate_config_hash(c)
        if h not in unique_map: unique_map[h] = c
    
    # 2. İsimlendirme
    final_configs = [rename_config_simple(c) for c in unique_map.values()]

    # 3. Yandex Disk'e Kaydet
    content = "\n".join(final_configs)
    if await yandex_upload(content):
        print(f"✅ Başarılı! {len(final_configs)} config Yandex Disk'e yüklendi.")
    else:
        print("❌ Yandex Disk yüklemesi başarısız.")

if __name__ == "__main__":
    asyncio.run(main())
