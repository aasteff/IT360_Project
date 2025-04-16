import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
import time
import json
import os

# -----------------------------
# CONFIG
# -----------------------------
TARGET_URL = input("Enter the URL of the page to scan for IOCs: ")
IOC_REPORT = "universal_ioc_report.txt"
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your VirusTotal API key
LOOKUP_LIMIT = 3  # Max number of VirusTotal lookups per type (reduced for large pages)
VT_DELAY = 15  # Seconds between VirusTotal requests
CACHE_FILE = "vt_cache.json"
MAX_TEXT_LINES = 200  # Limit number of lines to scan from large sources

# -----------------------------
# LOAD VT CACHE
# -----------------------------
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        vt_cache = json.load(f)
else:
    vt_cache = {}

# -----------------------------
# REGEX PATTERNS FOR IOC EXTRACTION
# -----------------------------
IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
HASH_PATTERN = r"\b[a-fA-F0-9]{64}\b"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b"
EMAIL_PATTERN = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
URL_PATTERN = r"https?://[\w./-]+"
IMAGE_PATTERN = r"https?://[^\s]+\.(?:jpg|jpeg|png|gif|bmp)"

# -----------------------------
# VIRUSTOTAL LOOKUPS
# -----------------------------
def check_vt(entity, entity_type):
    if entity in vt_cache:
        return vt_cache[entity]

    headers = {"x-apikey": VT_API_KEY}
    if entity_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{entity}"
    elif entity_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{entity}"
    else:
        return "Unknown"

    try:
        print(f"🔎 Looking up {entity} on VirusTotal...")
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        if 'data' in data:
            stats = data['data']['attributes']['last_analysis_stats']
            result = "🛑 Malicious" if stats['malicious'] > 0 else "✅ Clean"
        else:
            result = "❓ Not Found"
    except Exception as e:
        result = f"❌ Error"
        print(f"VT lookup failed for {entity}: {e}")

    vt_cache[entity] = result
    time.sleep(VT_DELAY)
    return result

# -----------------------------
# EXTRACT IOCs FROM ANY PAGE
# -----------------------------
def extract_iocs_from_page(url):
    try:
        print(f"📥 Fetching: {url}")
        r = requests.get(url, timeout=10)
        if url.endswith(".txt"):
            lines = r.text.splitlines()[:MAX_TEXT_LINES]
            text = "\n".join(lines)
            image_urls = re.findall(IMAGE_PATTERN, text)
        else:
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text()
            image_tags = soup.find_all('img')
            image_urls = [img.get('src') for img in image_tags if img.get('src') and re.match(r'^https?://', img.get('src'))]

        iocs = {
            "ips": sorted(set(re.findall(IP_PATTERN, text))),
            "hashes": sorted(set(re.findall(HASH_PATTERN, text))),
            "domains": sorted(set(re.findall(DOMAIN_PATTERN, text))),
            "emails": sorted(set(re.findall(EMAIL_PATTERN, text))),
            "urls": sorted(set(re.findall(URL_PATTERN, text))),
            "images": sorted(set(image_urls))
        }
        return iocs
    except Exception as e:
        print(f"❌ Error scraping {url}: {e}")
        return {}

# -----------------------------
# MAIN PROCESS
# -----------------------------
def main():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = [
        "=======================================================" ,
        "🌐 UNIVERSAL IOC SCRAPER (via BeautifulSoup)",
        "=======================================================",
        f"🕒 Generated: {now}",
        f"🔗 Scanned URL: {TARGET_URL}",
        "=======================================================\n"
    ]

    iocs = extract_iocs_from_page(TARGET_URL)

    def format_list(name, items, vt_type=None):
        report.append(f"🔸 {name} ({len(items)} found):")
        if items:
            for i, item in enumerate(items):
                if vt_type and i < LOOKUP_LIMIT:
                    verdict = check_vt(item, vt_type)
                    report.append(f"   - {item} ({verdict})")
                else:
                    report.append(f"   - {item}")
        else:
            report.append("   - None")
        report.append("")

    format_list("IP Addresses", iocs.get("ips", []))
    format_list("Domains", iocs.get("domains", []), vt_type="domain")
    format_list("Hashes (SHA256)", iocs.get("hashes", []), vt_type="hash")
    format_list("Emails", iocs.get("emails", []))
    format_list("URLs", iocs.get("urls", []))
    format_list("Image URLs", iocs.get("images", []))

    with open(IOC_REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(report))

    with open(CACHE_FILE, "w") as f:
        json.dump(vt_cache, f, indent=2)

    print(f"\n✅ Report saved to {IOC_REPORT}")

if __name__ == "__main__":
    main()
