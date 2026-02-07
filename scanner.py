import os
import sys
import asyncio
import aiohttp
import base64
import json
import re

sys.stdout.reconfigure(encoding='utf-8')

CONFIG_URL = os.getenv("CONFIG_URL")
PCLOUD_USERNAME = os.getenv("PCLOUD_USERNAME")
PCLOUD_PASSWORD = os.getenv("PCLOUD_PASSWORD")

MAX_CONFIG = 2000
TIMEOUT = 4
CONCURRENT = 300


# ⭐ rename counter
rename_counter = {}


# ---------------- PARSERS ---------------- #

def parse_vless_trojan(config):
    match = re.search(r'@([^:]+):(\d+)', config)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


def parse_vmess(config):
    try:
        encoded = config.replace("vmess://", "")
        decoded = base64.b64decode(encoded + "==").decode()
        data = json.loads(decoded)

        host = data.get("add")
        port = int(data.get("port"))

        return host, port
    except:
        return None, None


def parse_ss(config):
    try:
        content = config.replace("ss://", "")

        if "@" not in content:
            decoded = base64.b64decode(content + "==").decode()
        else:
            decoded = content

        match = re.search(r'@([^:]+):(\d+)', decoded)

        if match:
            return match.group(1), int(match.group(2))

    except:
        return None, None

    return None, None


def parse_host_port(config):

    if config.startswith("vless://"):
        return parse_vless_trojan(config)

    if config.startswith("trojan://"):
        return parse_vless_trojan(config)

    if config.startswith("vmess://"):
        return parse_vmess(config)

    if config.startswith("ss://"):
        return parse_ss(config)

    return None, None


# ---------------- TCP TEST ---------------- #

async def tcp_test(host, port):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)

        writer.close()
        await writer.wait_closed()

        return True

    except:
        return False


# ---------------- RENAME ---------------- #

def rename_config(config):

    proto = config.split("://")[0].upper()

    rename_counter[proto] = rename_counter.get(proto, 0) + 1

    name = f"{proto}{rename_counter[proto]}"

    if "#" in config:
        config = config.split("#")[0]

    return f"{config}#{name}"


# ---------------- FETCH ---------------- #

async def fetch_configs():

    async with aiohttp.ClientSession() as session:
        async with session.get(CONFIG_URL, timeout=20) as resp:
            text = await resp.text()

            return list(set(text.splitlines()))  # duplicate killer


# ---------------- SCAN ---------------- #

async def scan_configs(configs):

    semaphore = asyncio.Semaphore(CONCURRENT)
    working = []

    async def check(config):

        # HARD STOP
        if len(working) >= MAX_CONFIG:
            return

        host, port = parse_host_port(config)

        if not host:
            return

        async with semaphore:

            ok = await tcp_test(host, port)

        if ok:

            renamed = rename_config(config)

            working.append(renamed)

            print("WORKING:", len(working))

    await asyncio.gather(*(check(c) for c in configs), return_exceptions=True)

    return working[:MAX_CONFIG]


# ---------------- PCLOUD ---------------- #

async def pcloud_upload(content):

    login_url = "https://eapi.pcloud.com/login"
    upload_url = "https://eapi.pcloud.com/uploadfile"

    async with aiohttp.ClientSession() as session:

        async with session.get(login_url, params={
            "username": PCLOUD_USERNAME,
            "password": PCLOUD_PASSWORD
        }) as resp:

            data = await resp.json()
            auth = data["auth"]

        form = aiohttp.FormData()

        form.add_field(
            "file",
            content,
            filename="working_configs.txt"
        )

        async with session.post(
            upload_url + f"?auth={auth}&folderid=0&filename=working_configs.txt",
            data=form
        ) as resp:

            result = await resp.json()

            print("UPLOAD OK")


# ---------------- MAIN ---------------- #

async def main():

    print("Fetching configs...")
    configs = await fetch_configs()

    print("Scanning started...")

    working = await scan_configs(configs)

    print("TOTAL WORKING:", len(working))

    if working:
        await pcloud_upload("\n".join(working))


asyncio.run(main())
