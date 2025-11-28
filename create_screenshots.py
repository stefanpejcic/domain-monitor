import requests
import os

# this is optional, if screnshot not exist locally, they will be auto generated on page load

def read_domains():
    with open("domains.txt", "r") as f:
        return [line.strip() for line in f if line.strip()]

def fetch_screenshot(domain):
    url = f"https://screenshots-v3.openpanel.com/api/screenshot/{domain}"
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        os.makedirs("screenshots", exist_ok=True)
        file_path = f"screenshots/{domain}.png"
        with open(file_path, "wb") as f:
            f.write(r.content)
        print(f"Screenshot saved for {domain} → {file_path}")
    except Exception as e:
        print(f"[Screenshot] Failed for {domain}: {e}")

def main():
    domains = read_domains()
    for domain in domains:
        fetch_screenshot(domain)

if __name__ == "__main__":
    main()
