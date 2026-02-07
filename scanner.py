import os
import asyncio
import aiohttp
import socket
import re
import sys
sys.stdout.reconfigure(encoding='utf-8')

CONFIG_URL = os.getenv("CONFIG_URL")

PCLOUD_USERNAME = os.getenv("PCLOUD_USERNAME")
PCLOUD_PASSWORD = os.getenv("PCLOUD_PASSWORD")

MAX_CONFIG = 2000
TIMEOUT = 4
CONCURRENT = 200


# 🌍 Flag map (genişletilebilir)
FLAG_MAP = {
    "DE": "🇩🇪GER",
    "TR": "🇹🇷TUR",
    "PL": "🇵🇱POL",
    "US": "🇺🇸USA",
    "NL": "🇳🇱NED",
    "FR": "🇫🇷FRA",
    "GB": "🇬🇧UK",
    "KZ": "🇰🇿KAZ"
}


def parse_host_port(config):
    match = re.search(r'@([^:]+):(\d+)', config)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


async def tcp_test(host, port):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False


def detect_country(config):
    for key in FLAG_MAP:
        if key.lower() in config.lower():
            return FLAG_MAP[key]
    return "🌍UNK"


async def fetch_configs():
    async with aiohttp.ClientSession() as session:
        async with session.get(CONFIG_URL, timeout=20) as resp:
            text = await resp.text()
            return text.splitlines()


async def scan_configs(configs):
    semaphore = asyncio.Semaphore(CONCURRENT)
    working = []
    counter = {}

    async def check(config):
        nonlocal working

        if len(working) >= MAX_CONFIG:
            return

        host, port = parse_host_port(config)
        if not host:
            return

        async with semaphore:
            ok = await tcp_test(host, port)

        if ok:
            country = detect_country(config)
            counter[country] = counter.get(country, 0) + 1

            name = f"{country}{counter[country]}-vless"

            final = f"{config}#{name}"
            working.append(final)

            print("✔", name)

    await asyncio.gather(*(check(c) for c in configs))

    return working[:MAX_CONFIG]


async def pcloud_upload(content):

    login_url = "https://api.pcloud.com/login"
    upload_url = "https://api.pcloud.com/uploadfile"

    async with aiohttp.ClientSession() as session:

        # login
        async with session.get(login_url, params={
            "username": PCLOUD_USERNAME,
            "password": PCLOUD_PASSWORD
        }) as resp:

            data = await resp.json()
            auth = data["auth"]

        # upload
        form = aiohttp.FormData()
        form.add_field("file",
                       content,
                       filename="working_configs.txt")

        async with session.post(
            upload_url + f"?auth={auth}&filename=working_configs.txt&folderid=0",
            data=form
        ) as resp:

            result = await resp.json()
            print("UPLOAD:", result)


async def main():

    print("Fetching configs...")
    configs = await fetch_configs()

    print("Scanning...")
    working = await scan_configs(configs)

    print("FOUND:", len(working))

    if working:
        await pcloud_upload("\n".join(working))


asyncio.run(main())
