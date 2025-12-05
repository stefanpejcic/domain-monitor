import whois
import requests
import socket, ssl
from datetime import datetime, timedelta, timezone
import os
import re
import json
import xml.etree.ElementTree as ET
import tldextract
from urllib.parse import urlparse
import ipaddress

cf_ranges_cache = None  # global cache for Cloudflare IPs
vercel_cidrs = ["76.76.21.0/24", "64.29.17.0/24", "66.33.60.0/24", "216.198.79.0/24"]
vercel_networks = [ipaddress.IPv4Network(cidr) for cidr in vercel_cidrs]

def read_domains():
    with open("domains.txt", "r") as f:
        return [line.strip() for line in f if line.strip()]

def sanitize_filename(name):
    name = re.sub(r'^https?://', '', name)
    name = re.sub(r':\d+$', '', name)
    name = re.sub(r'[^a-zA-Z0-9.-]', '_', name)
    return name

def get_apex_domain(domain):
    ext = tldextract.extract(domain)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain


def get_hostname_port(domain_or_url, default_port=443):
    if "://" not in domain_or_url:
        domain_or_url = "https://" + domain_or_url
    parsed = urlparse(domain_or_url)
    hostname = parsed.hostname
    port = parsed.port if parsed.port else default_port
    return hostname, port

def is_ip_vercel(ip):
    ip_addr = ipaddress.IPv4Address(ip)
    return any(ip_addr in net for net in vercel_networks)

def get_cloudflare_ips_cached():
    global cf_ranges_cache
    if cf_ranges_cache is not None:
        return cf_ranges_cache

    try:
        r = requests.get("https://www.cloudflare.com/ips-v4", timeout=5)
        if r.status_code == 200:
            cf_list = [line.strip() for line in r.text.splitlines() if line.strip()]
            cf_ranges_cache = {cidr: ipaddress.IPv4Network(cidr) for cidr in cf_list}
            print(f"[Cloudflare IPs] Fetched and cached {len(cf_ranges_cache)} ranges")
            return cf_ranges_cache
    except Exception as e:
        print(f"[Cloudflare IPs] Error fetching Cloudflare IP ranges: {e}")

    cf_ranges_cache = {}
    return cf_ranges_cache

def is_ip_in_cloudflare_cached(ip):
    cf_dict = get_cloudflare_ips_cached()
    if not cf_dict:
        return False

    ip_addr = ipaddress.IPv4Address(ip)
    for network in cf_dict.values():
        if ip_addr in network:
            return True
    return False

def get_whois_info(domain):
    try:
        w = whois.whois(domain)

        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]

        registrar = w.registrar if hasattr(w, 'registrar') else None

        print(f"[WHOIS] For {domain} | exp: {exp} | registrar: {registrar}")
        return exp, registrar
    except Exception as e:
        print(f"[WHOIS] Error checking {domain}: {e}")
        return None, None

def get_dns_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [rdata.to_text().lower().strip('.') for rdata in answers]
    except Exception as e:
        print(f"[DNS] Error getting NS for {domain}: {e}")
        return []


def get_ssl_expiration(domain, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_str = cert['notAfter']
                exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                print(f"[SSL] For {domain}:{port} | exp_date: {exp_date}")
                return exp_date
    except Exception as e:
        print(f"[SSL] Error checking {domain}:{port}: {e}")
        return None

def get_http_status(url, session):
    try:
        r = session.get(url, timeout=10)
        response_time_ms = r.elapsed.total_seconds() * 1000
        print(f"[HTTP] For {url} | status: {r.status_code} | response_time: {response_time_ms}")
        return r.status_code, response_time_ms
    except Exception as e:
        print(f"[HTTP] Error checking {url}: {e}")
        return None, None

def load_domain_history(domain):
    file = f"status/history/{sanitize_filename(domain)}.json"
    if os.path.exists(file):
        print(f"[load_domain_history] For {domain} | reading JSON from file: {file}")
        with open(file, "r") as f:
            return json.load(f)
    print(f"[load_domain_history] For {domain} | JSON file does not exist: {file}")
    return {"domain": domain, "history": []}

def save_domain_history(domain, history):
    os.makedirs("status/history", exist_ok=True)
    file = f"status/history/{sanitize_filename(domain)}.json"
    with open(file, "w") as f:
        json.dump(history, f, indent=2)
    print(f"[save_domain_history] For {domain} | Saved JSON to {file}")

def load_domain_xml(domain):
    file = f"status/history/{sanitize_filename(domain)}.xml"
    if os.path.exists(file):
        tree = ET.parse(file)
        print(f"[load_domain_xml] For {domain} | reading from XML file: {file}")
        return tree, tree.getroot()

    root = ET.Element("domain_history")
    root.set("domain", domain)
    tree = ET.ElementTree(root)
    print(f"[load_domain_xml] For {domain} | XML file does not exist: {file}")
    return tree, root

def save_domain_xml(domain, tree):
    file = f"status/history/{sanitize_filename(domain)}.xml"
    ET.indent(tree, space="  ")
    tree.write(file, encoding="utf-8", xml_declaration=True)
    print(f"[save_domain_xml] Saved XML history for {domain} → {file}")

def get_outgoing_ip():
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=1)
        return r.json().get("ip")
    except Exception as e:
        print(f"[IP] Error checking Github Worker's outgoing IP: {e}")
        return None

def main():
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")
    days_threshold = int(os.getenv("DAYS_THRESHOLD", "29"))
    response_threshold = int(os.getenv("RESPONSE_THRESHOLD", "1000"))
    
    print("==============================================")
    print("                Domain Monitor                ")
    print("==============================================")

    # ---- Get github worker or server IP ----
    outgoing_ipv4 = get_outgoing_ip()
    print(f"Outgoing IP: {outgoing_ipv4}")

    # ---- GH actions, check issues ----
    from github import Github, Auth
    print("Running in: GitHub Actions")
    g = Github(auth=Auth.Token(token))
    repo = g.get_repo(repo_name)

    open_issues = {issue.title: issue for issue in repo.get_issues(state="open")}

    def find_issue(keyword):
        for title, issue in open_issues.items():
            if keyword in title:
                return issue
        return None

    def create_issue(title, body):
        issue = repo.create_issue(title=title, body=body)
        open_issues[title] = issue  # update cache
        print(f"Issue created: {title}")
        return issue

    def close_issue(issue, msg):
        issue.create_comment(msg)
        issue.edit(state="closed")
        print(f"Issue closed: {issue.title}")
        open_issues.pop(issue.title, None)  # remove from cache

    def comment_on_issue(issue, msg):
        issue.create_comment(msg)
        print(f"Comment added to issue: {issue.title}")

    # ---- HTTP session ----
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Github Actions - stefanpejcic/domain-monitor/1.0",
        "X-Github-Repository": repo.full_name
    })

    combined_results = {
        "domains": [],
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": outgoing_ipv4
    }

    # ---- domains.txt ----
    domains = list(dict.fromkeys(read_domains()))  # deduplicate 
    for domain in domains:
        print(f"[PREPARATION] checking domain: {domain}")

        # ---- preparation ----
        hostname, port = get_hostname_port(domain)
        url = f"https://{domain}" if "://" not in domain else domain

        now = datetime.utcnow()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        apex = get_apex_domain(domain)

        # ---- Read existing JSON and read previous data ----
        domain_history = load_domain_history(domain)
        last_entry = domain_history["history"][-1] if domain_history["history"] else None
        checked_in_last_24h = False
        if last_entry and "timestamp" in last_entry:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            previous_timestamp = datetime.strptime(last_entry["timestamp"], "%Y-%m-%d %H:%M:%S")
            if timestamp - previous_timestamp < timedelta(hours=24):
                checked_in_last_24h = True  

        if not checked_in_last_24h:            # use data from previous check
            exp_date, registrar = get_whois_info(apex)
            nameservers = get_dns_nameservers(apex)
            ssl_exp = get_ssl_expiration(hostname, port)
        else:                                  # run whois check
            exp_date = datetime.strptime(domain_history["whois_expiry"], "%Y-%m-%d") if domain_history.get("whois_expiry") else None
            registrar = domain_history.get("registrar")
            nameservers = domain_history.get("nameservers")
            ssl_exp = datetime.strptime(domain_history["ssl_expiry"], "%Y-%m-%d") if domain_history.get("ssl_expiry") else None

        # ---- WHOIS Expiration --- #
        days_left = None
        if exp_date:
            if exp_date.tzinfo is not None:
                exp_date = exp_date.astimezone(timezone.utc).replace(tzinfo=None)
            days_left = (exp_date - now).days
            issue = find_issue(f"Domain {domain} expires in")
            if days_left <= days_threshold:
                if not issue:
                    create_issue(
                        f"⚠️ Domain {domain} expires in {days_left} days!",
                        f"**{domain}** will expire on {exp_date:%Y-%m-%d}.\nDays left: {days_left}"
                    )
                else:
                    comment_on_issue(issue, f"@stefanpejcic Reminder: **{domain}** still expires in {days_left} days (on {exp_date:%Y-%m-%d}).")
            else:
                if issue:
                    close_issue(issue, f"✅ Domain {domain} renewed (expires {exp_date:%Y-%m-%d}, {days_left} days left).")

        # ---- WHOIS registrar --- #
        previous_registrar = last_entry.get("registrar") if last_entry else None
        if previous_registrar:
            if registrar != previous_registrar:
                issue = find_issue(f"Registar changed for domain: {domain}")
                if not issue:
                    create_issue(
                        f"🚨 Registar changed for domain: {domain} to: {registrar}",
                        f"**{domain}** register on last check was: {previous_registrar}.\nNew register information: {registrar}"
                    )
                else:
                    comment_on_issue(issue, f"@stefanpejcic Reminder: **{domain}** register info was changed from: {previous_registrar} to: {registrar}\nCheck domain WHOIS information ASAP!")
            # no else, this need to be manually closed! 

        # ---- SSL Expiration ---- #
        ssl_days = None
        issue = find_issue(f"SSL for {domain}")
        if ssl_exp:
            ssl_days = (ssl_exp - now).days
            if ssl_days <= days_threshold:
                if not issue:
                    create_issue(
                        f"🔒 SSL for {domain} expires in {ssl_days} days!",
                        f"SSL cert for **{domain}** expires on {ssl_exp:%Y-%m-%d}.\nDays left: {ssl_days}"
                    )
            else:
                if issue:
                    close_issue(issue, f"✅ SSL for {domain} renewed (expires {ssl_exp:%Y-%m-%d}, {ssl_days} days left).")

        # ---- HTTP response time ----
        status, resp_time = get_http_status(url, session)
        resp_time_text = f"{resp_time:.0f} ms" if resp_time is not None else "N/A"

        issue = find_issue(f"Slow response for {domain}")
        if resp_time and resp_time > response_threshold:
            if not issue:
                create_issue(
                    f"⚠️ Slow response for {domain}",
                    f"HTTP response time is {resp_time_text} (threshold {response_threshold} ms)."
                )
        else:
            if issue:
                close_issue(issue, f"✅ {domain} is healthy again, response time {resp_time_text}).")

        # ---- Status code ----
        issue = find_issue(f"Status check failed for {domain}")
        if status is None:
            if not issue:
                create_issue(
                    f"❌ Status check failed for {domain} | URL: {url}",
                    f"Latest HTTP response code: `{status}`"
                )
            else:
                comment_on_issue(issue, f"Still no HTTP status code received.")
        elif status >= 400:
            if not issue:
                create_issue(
                    f"❌ Status check failed for {domain} | URL: {url}",
                    f"Latest HTTP response code: `{status}`"
                )
        else:
            if issue:
                close_issue(issue, f"✅ {domain} is healthy again, status code: {status}).")


        # ---- Check if NS changed ----
        previous_ns = last_entry.get("nameservers") if last_entry else None
        ip_issue = find_issue(f"Nameservers change detected for {domain}")
        
        if previous_ns and nameservers and previous_ns != nameservers:
            if not ip_issue:
                create_issue(
                    f"🚨 Nameservers change detected for {domain} ({nameservers})",
                    f"Domain **{domain}** NS changed from `{previous_ns}` to `{nameservers}`"
                )
            else:
                comment_on_issue(ip_issue, f"NS updated to `{nameservers}`")
                ip_issue.edit(title=f"🚨 Nameservers change detected for {domain} from `{previous_ns}` to `{nameservers}`")


        # ---- Check if IPv4 changed ---- #
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception as e:
            print(f"[DNS] Error resolving {hostname}: {e}")
            resolved_ip = None

        previous_ip = last_entry.get("resolved_ip") if last_entry else None

        if resolved_ip and previous_ip and previous_ip != resolved_ip:
            if is_ip_in_cloudflare_cached(resolved_ip):
                print(f"[DNS] {hostname} resolves to Cloudflare IP {resolved_ip}, ignoring for IP change detection.")
            elif is_ip_vercel(resolved_ip):
                print(f"[DNS] {hostname} resolves to Vercel IP {resolved_ip}, ignoring for IP change detection.")            
            else:
                ip_issue = find_issue(f"IP change detected for {domain}")
                if not ip_issue:
                    create_issue(
                        f"🚨 IP change detected for {domain} ({resolved_ip})",
                        f"Domain **{domain}** IP changed from `{previous_ip}` to `{resolved_ip}`"
                    )
                else:
                    comment_on_issue(ip_issue, f"IP updated to `{resolved_ip}`")
                    ip_issue.edit(title=f"🚨 IP change detected for {domain} from `{previous_ip}` to `{resolved_ip}`")

        # ---- Checks completed for domain, saving.. ----
        domain_entry = {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(timestamp, datetime) else timestamp,
            "whois_ok": days_left > days_threshold if days_left is not None else False,
            "ssl_ok": ssl_days > days_threshold if ssl_days is not None else False,
            "http_status": status,
            "http_ok": status is not None and status < 400,
            "http_response_time_ms": resp_time,
            "resolved_ip": resolved_ip
        }
        
        extra_fields = {
            "ip_address": outgoing_ipv4,
            "whois_expiry": exp_date.strftime("%Y-%m-%d") if exp_date else None,
            "nameservers": nameservers if nameservers else None,
            "registrar": registrar,
            "ssl_expiry": ssl_exp.strftime("%Y-%m-%d") if ssl_exp else None
        }

        # ---- Save JSON for domain --- #
        domain_history["history"].append(domain_entry)
        domain_history.update(extra_fields)
        save_domain_history(domain, domain_history)

        # ---- Save XML for domain ----
        tree, root = load_domain_xml(domain)
        entry_xml = ET.SubElement(root, "entry")
        
        for key, value in domain_entry.items():
            el = ET.SubElement(entry_xml, key)
            el.text = str(value)
        
        extra_xml = ET.SubElement(root, "extra")
        for key, value in extra_fields.items():
            el = ET.SubElement(extra_xml, key)
            el.text = str(value)
        
        save_domain_xml(domain, tree)
        
        combined_results["domains"].append({
            "domain": domain,
            "history_entry": domain_entry,
            **extra_fields
        })

    # ---- Save combined data to status.json ----
    os.makedirs("status", exist_ok=True)
    with open("status/status.json", "w") as f:
        print("Saving combined results in status/status.json")
        json.dump(combined_results, f, indent=2)

    # ---- Save combined data to index.xml ----
    root = ET.Element("domains_report")
    root.set("last_updated", combined_results["last_updated"])
    root.set("ip_address", combined_results["ip_address"])

    for item in combined_results["domains"]:
        domain_el = ET.SubElement(root, "domain")
        domain_el.set("name", item["domain"])

        for key, value in item.items():
            if key == "domain":
                continue
            child = ET.SubElement(domain_el, key)
            child.text = str(value)

    tree = ET.ElementTree(root)
    tree.write("status/index.xml", encoding="utf-8", xml_declaration=True)
    print("Generated status/index.xml")


if __name__ == "__main__":
    main()
