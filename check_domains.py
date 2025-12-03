import whois
import requests
import socket, ssl
from datetime import datetime, timezone
import os
import re
import json
import xml.etree.ElementTree as ET
import tldextract
from urllib.parse import urlparse


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

def get_whois_info(domain):
    # TODO: also detect ns change
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):  # sometimes a list
            exp = exp[0]
        print(f"[WHOIS] For {domain} | exp: {exp}")

        ns = w.nameservers if hasattr(w, "nameservers") else []
        if ns:
            ns = [n.lower().strip(".") for n in ns]
        
        print(f"[WHOIS] For {domain} | exp: {exp} | NS: {ns}")
        return {"expiration_date": exp, "nameservers": ns}
    except Exception as e:
        print(f"[WHOIS] Error checking {domain}: {e}")
        return {"expiration_date": None, "nameservers": []}

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
    days_threshold = int(os.getenv("DAYS_THRESHOLD", "30"))
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

        # ---- get hostname and url ----
        hostname, port = get_hostname_port(domain)

        if "://" not in domain:
            url = f"https://{domain}"
            #if port != 443:
            #    url += f":{port}"
        else:
            url = domain


        now = datetime.utcnow()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

        # ---- WHOIS Expiration ----
        whois_cache = {}       
        apex = get_apex_domain(domain)
        if apex in whois_cache:
            info = whois_cache[apex]
            print(f"[WHOIS] For {domain} reusing existing info from {apex}")
        else:
            info = get_whois_info(apex)
            whois_cache[apex] = info

        exp_date = info["expiration_date"]
        nameservers = info["nameservers"]
        
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

        # ---- SSL Expiration ----
        ssl_exp = get_ssl_expiration(hostname, port)
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

        # ---- HTTP Status ----
        status, resp_time = get_http_status(url, session)
        resp_time_text = f"{resp_time:.0f} ms" if resp_time is not None else "N/A"
        issue = find_issue(f"Slow response for {domain}") # todo: cover statuses!
        if status is None or status >= 400:
            if not issue:
                create_issue(
                    f"❌ Status check failed for {domain} | URL: {url}",
                    f"Latest HTTP response: `{status}`, response time: {resp_time_text} ms"
                )
        elif resp_time and resp_time > response_threshold:
            if not issue:
                create_issue(
                    f"⚠️ Slow response for {domain}",
                    f"HTTP response time is {resp_time_text} (threshold {response_threshold} ms)."
                )
        else:
            if issue:
                close_issue(issue, f"✅ {domain} is healthy again (status {status}, response time {resp_time_text}).")

        # ---- Update per-domain JSON ----
        domain_history = load_domain_history(domain)

        # ---- Check if NS changed ----
        last_entry = domain_history["history"][-1] if domain_history["history"] else None
        previous_ns = last_entry.get("nameservers") if last_entry else None
        ip_issue = find_issue(f"Nameservers change detected for {domain}")
        
        last_reported_ns = None
        if ip_issue:
            import re
            m = re.search(r"\(was ([\d\.]+)\)", ip_issue.title)
            if m:
                last_reported_ns = m.group(1)
        
        if last_reported_ns:
            if nameservers and last_reported_ns != resolved_ns:
                if not ip_issue:
                    create_issue(
                        f"🚨 Nameservers change detected for {domain} (was {previous_ns})",
                        f"Domain **{domain}** NS changed from `{previous_ns}` to `{nameservers}`"
                    )
                else:
                    comment_on_issue(ip_issue, f"NS updated to `{nameservers}`")
                    ip_issue.edit(title=f"🚨 Nameservers change detected for {domain} (was {previous_ns})")

        # ---- Check if IPv4 changed ---- #
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception as e:
            print(f"[DNS] Error resolving {hostname}: {e}")
            resolved_ip = None
        """
        # temporary off
        last_entry = domain_history["history"][-1] if domain_history["history"] else None
        previous_ip = last_entry.get("resolved_ip") if last_entry else None
        ip_issue = find_issue(f"IP change for {domain}")
        
        last_reported_ip = None
        if ip_issue:
            import re
            m = re.search(r"\(was ([\d\.]+)\)", ip_issue.title)
            if m:
                last_reported_ip = m.group(1)
        
        if resolved_ip and last_reported_ip != resolved_ip:
            if not ip_issue:
                create_issue(
                    f"🚨 IP change detected for {domain} (was {previous_ip})",
                    f"Domain **{domain}** IP changed from `{previous_ip}` to `{resolved_ip}`"
                )
            else:
                comment_on_issue(ip_issue, f"IP updated to `{resolved_ip}`")
                ip_issue.edit(title=f"🚨 IP change detected for {domain} (was {previous_ip})")
        """

        # ---- Checks completed for domain, saving.. ----
        domain_entry = {
            "timestamp": timestamp,
            "whois_expiry": exp_date.strftime("%Y-%m-%d") if exp_date else None,
            "whois_ok": days_left > days_threshold if days_left is not None else False,
            "nameservers": nameservers if nameservers else None,
            "ssl_expiry": ssl_exp.strftime("%Y-%m-%d") if ssl_exp else None,
            "ssl_ok": ssl_days > days_threshold if ssl_days is not None else False,
            "http_status": status,
            "http_ok": status is not None and status < 400,
            "http_response_time_ms": resp_time,
            "resolved_ip": resolved_ip
        }
        
        # ---- Save JSON for domain ----
        domain_history["history"].append({**domain_entry, "ip_address": outgoing_ipv4})
        save_domain_history(domain, domain_history)
        # ---- Save XML for domain ----
        tree, root = load_domain_xml(domain)
        entry_xml = ET.SubElement(root, "entry")
        for key, value in {**domain_entry, "ip_address": outgoing_ipv4}.items():
            el = ET.SubElement(entry_xml, key)
            el.text = str(value)
        save_domain_xml(domain, tree)
        # ---- Add domain to the dictionary for combined JSON/XML files ----
        combined_results["domains"].append({**domain_entry, "domain": domain})

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
