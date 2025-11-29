import whois
import requests
import socket, ssl
from datetime import datetime, timezone
from github import Github, Auth
import os
import json
import xml.etree.ElementTree as ET
import tldextract

whois_cache = {}

def read_domains():
    with open("domains.txt", "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_apex_domain(domain):
    ext = tldextract.extract(domain)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain

def get_domain_expiration(domain):
    # TODO: also detect ns change
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):  # sometimes a list
            exp = exp[0]
        return exp
    except Exception as e:
        print(f"[WHOIS] Error checking {domain}: {e}")
        return None

def get_ssl_expiration(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_str = cert['notAfter']
                exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                return exp_date
    except Exception as e:
        print(f"[SSL] Error checking {domain}: {e}")
        return None

def get_http_status(domain, headers):
    try:
        url = f"https://{domain}"
        r = requests.get(url, headers=headers, timeout=10)
        response_time_ms = r.elapsed.total_seconds() * 1000
        return r.status_code, response_time_ms
    except Exception as e:
        print(f"[HTTP] Error checking {domain}: {e}")
        return None, None

# ---- Get all GitHub issues ----
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
    

def load_domain_history(domain):
    history_file = f"status/history/{domain}.json"
    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            return json.load(f)
    return {"domain": domain, "history": []}

def save_domain_history(domain, history):
    os.makedirs("status/history", exist_ok=True)
    history_file = f"status/history/{domain}.json"
    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)
    print(f"Saved history for {domain} in {history_file}")

def load_domain_xml(domain):
    xml_file = f"status/history/{domain}.xml"
    if os.path.exists(xml_file):
        tree = ET.parse(xml_file)
        return tree, tree.getroot()

    root = ET.Element("domain_history")
    root.set("domain", domain)
    tree = ET.ElementTree(root)
    return tree, root

def save_domain_xml(domain, tree):
    xml_file = f"status/history/{domain}.xml"
    ET.indent(tree, space="  ")
    tree.write(xml_file, encoding="utf-8", xml_declaration=True)
    print(f"Saved XML history for {domain} → {xml_file}")

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

    g = Github(auth=Auth.Token(token))
    repo = g.get_repo(repo_name)

    # ---- Get github worker IP ----
    gh_actions_ip = get_outgoing_ip()
    print(f"Outgoing IP: {gh_actions_ip}")

    # ---- HTTP session ----
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Github Actions - stefanpejcic/domain-monitor/1.0",
        "X-Github-Repository": repo.full_name
    })


    combined_results = {
        "domains": [],
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": gh_actions_ip
    }

    # ---- domains.txt ----
    domains = read_domains()
    for domain in domains:
        print(f"[PREPARATION] checking domain: {domain}")
        now = datetime.utcnow()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

        # ---- WHOIS Expiration ----
        apex = get_apex_domain(domain)
        if apex in whois_cache:
            exp_date = whois_cache[apex]
            print(f"[WHOIS] For {domain} reusing existing whois information from {apex}")
        else:
            print(f"[WHOIS] For {domain} checking whois information from {apex}")
            exp_date = get_domain_expiration(apex)

        days_left = None
        if exp_date:
            if exp_date.tzinfo is not None:
                exp_date = exp_date.astimezone(timezone.utc).replace(tzinfo=None)
            days_left = (exp_date - now).days
            issue = find_issue(repo, f"Domain {domain} expires in")
            if days_left <= days_threshold:
                if not issue:
                    create_issue(
                        repo,
                        f"⚠️ Domain {domain} expires in {days_left} days!",
                        f"**{domain}** will expire on {exp_date:%Y-%m-%d}.\nDays left: {days_left}"
                    )
                else:
                    comment_on_issue(issue, f"@stefanpejcic Reminder: **{domain}** still expires in {days_left} days (on {exp_date:%Y-%m-%d}).")
            else:
                if issue:
                    close_issue(issue, f"✅ Domain {domain} renewed (expires {exp_date:%Y-%m-%d}, {days_left} days left).")

        # ---- SSL Expiration ----
        ssl_exp = get_ssl_expiration(domain)
        ssl_days = None
        issue = find_issue(repo, f"SSL for {domain}")
        if ssl_exp:
            ssl_days = (ssl_exp - now).days
            if ssl_days <= days_threshold:
                if not issue:
                    create_issue(
                        repo,
                        f"🔒 SSL for {domain} expires in {ssl_days} days!",
                        f"SSL cert for **{domain}** expires on {ssl_exp:%Y-%m-%d}.\nDays left: {ssl_days}"
                    )
            else:
                if issue:
                    close_issue(issue, f"✅ SSL for {domain} renewed (expires {ssl_exp:%Y-%m-%d}, {ssl_days} days left).")

        # ---- HTTP Status ----
        status, resp_time = get_http_status(domain, session)
        issue = find_issue(repo, f"Slow response for {domain}")
        if status is None or status >= 400:
            if not issue:
                create_issue(
                    repo,
                    f"❌ Status check failed for {domain}",
                    f"Latest HTTP response: `{status}`, response time: {resp_time:.0f} ms"
                )
        elif resp_time and resp_time > response_threshold:
            if not issue:
                create_issue(
                    repo,
                    f"⚠️ Slow response for {domain}",
                    f"HTTP response time is {resp_time:.0f} ms (threshold {response_threshold} ms)."
                )
        else:
            if issue:
                close_issue(issue, f"✅ {domain} is healthy again (status {status}, response time {resp_time:.0f} ms).")

        # ---- Update per-domain JSON ----
        domain_history = load_domain_history(domain)

        # ---- Resolve domain IP ----
        # we need domain_history for this!
        try:
            resolved_ip = socket.gethostbyname(domain)
        except Exception as e:
            print(f"[DNS] Error resolving {domain}: {e}")
            resolved_ip = None
        """
        # temporary off
        last_entry = domain_history["history"][-1] if domain_history["history"] else None
        previous_ip = last_entry.get("resolved_ip") if last_entry else None
        ip_issue = find_issue(repo, f"IP change for {domain}")
        
        last_reported_ip = None
        if ip_issue:
            import re
            m = re.search(r"\(was ([\d\.]+)\)", ip_issue.title)
            if m:
                last_reported_ip = m.group(1)
        
        if resolved_ip and last_reported_ip != resolved_ip:
            if not ip_issue:
                create_issue(
                    repo,
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
            "ssl_expiry": ssl_exp.strftime("%Y-%m-%d") if ssl_exp else None,
            "ssl_ok": ssl_days > days_threshold if ssl_days is not None else False,
            "http_status": status,
            "http_ok": status is not None and status < 400,
            "http_response_time_ms": resp_time,
            "resolved_ip": resolved_ip
        }
        
        # ---- Save JSON for domain ----
        domain_history["history"].append({**domain_entry, "ip_address": gh_actions_ip})
        save_domain_history(domain, domain_history)
        # ---- Save XML for domain ----
        tree, root = load_domain_xml(domain)
        entry_xml = ET.SubElement(root, "entry")
        for key, value in {**domain_entry, "ip_address": gh_actions_ip}.items():
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
