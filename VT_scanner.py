
import requests
import time
import os

# Configuration
INPUT_FILE = "file.txt" # Put your file here
API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxx" #put your api key here

BASE_URL = "https://www.virustotal.com/api/v3/urls"

HEADERS = {
    "x-apikey": API_KEY
}

# Output files
OUTPUT_FILES = {
    "clean": "clean.txt",
    "malicious": "malicious.txt",
}

def submit_url(url):
    """Submit URL to VirusTotal for analysis."""

    response = requests.post(
        BASE_URL,
        headers=HEADERS,
        data={"url": url},
        timeout=30
    )

    response.raise_for_status()

    return response.json()["data"]["id"]


def get_analysis(analysis_id):
    """Retrieve URL analysis results."""

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    response = requests.get(
        analysis_url,
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()

    return response.json()["data"]["attributes"]


def classify_url(stats):

    malicious = stats.get("malicious", 0)

    if malicious >= 1:
        return "malicious"

    else:
        return "clean"

def save_result(url, category):

    with open(OUTPUT_FILES[category], "a", encoding="utf-8") as file:
        file.write(url + "\n")


def scan_url(url):

    try:
        print(f"\n[+] Scanning: {url}")

        analysis_id = submit_url(url)

        # Wait for analysis completion
        for attempt in range(12):

            time.sleep(5)

            analysis = get_analysis(analysis_id)

            if analysis.get("status") == "completed":

                stats = analysis.get("stats", {})

                category = classify_url(stats)

                save_result(url, category)

                print(f"[{category.upper()}] {url}")
                print(f"Stats: {stats}")

                return category

        print(f"[TIMEOUT] {url}")
        save_result(url, "unknown")

        return "unknown"

    except requests.exceptions.HTTPError as error:

        print(f"[HTTP ERROR] {url}: {error}")

    except requests.exceptions.RequestException as error:

        print(f"[CONNECTION ERROR] {url}: {error}")

    except (KeyError, ValueError) as error:

        print(f"[DATA ERROR] {url}: {error}")

    save_result(url, "unknown")

    return "unknown"


def main():

    if not API_KEY:
        print("[-] Set your VT_API_KEY environment variable.")
        return

    if not os.path.exists(INPUT_FILE):
        print("[-] Input file not found.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        urls = list(dict.fromkeys(
            line.strip() for line in file if line.strip()
        ))

    print(f"[+] Total URLs: {len(urls)}")

    results = {
        "clean": 0,
        "malicious": 0,
        "suspicious": 0,
        "unknown": 0
    }

    for index, url in enumerate(urls, start=1):

        print(f"\n[{index}/{len(urls)}]")

        category = scan_url(url)

        results[category] += 1

        # Respect API rate limits
        time.sleep(15)

    print("\n========== SCAN SUMMARY ==========")

    for category, count in results.items():
        print(f"{category.upper()}: {count}")

    print("==================================")


if __name__ == "__main__":
    main()
