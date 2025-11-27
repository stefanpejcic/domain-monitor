import whois
import requests
import socket, ssl
from datetime import datetime, timezone
from github import Github, Auth
import os
import json

DOMAINS_FILE = "domains.txt"

def read_domains(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_domain_expiration(domain):
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):  # sometimes it's a list
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

def get_http_status(domain):
    try:
        url = f"https://{domain}"
        r = requests.get(url, timeout=10)
        response_time_ms = r.elapsed.total_seconds() * 1000
        return r.status_code, response_time_ms
    except Exception as e:
        print(f"[HTTP] Error checking {domain}: {e}")
        return None, None

def find_issue(repo, keyword):
    """Find an open issue containing the keyword in title."""
    issues = repo.get_issues(state="open")
    for issue in issues:
        if keyword in issue.title:
            return issue
    return None

def create_issue(repo, title, body):
    repo.create_issue(title=title, body=body)
    print(f"Issue created: {title}")

def close_issue(issue, msg):
    issue.create_comment(msg)
    issue.edit(state="closed")
    print(f"Issue closed: {issue.title}")

def main():
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")
    days_threshold = int(os.getenv("DAYS_THRESHOLD", "30"))
    response_threshold = int(os.getenv("RESPONSE_THRESHOLD", "1000"))

    g = Github(auth=Auth.Token(token))
    repo = g.get_repo(repo_name)

    domains = read_domains(DOMAINS_FILE)
    results = {"domains": [], "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    for domain in domains:
        # ---- WHOIS Expiration ----
        exp_date = get_domain_expiration(domain)
        if exp_date:
            if exp_date.tzinfo is not None:
                exp_date = exp_date.astimezone(timezone.utc).replace(tzinfo=None)
        
            now = datetime.utcnow()
            days_left = (exp_date - now).days        
            issue = find_issue(repo, f"Domain {domain}")
            if days_left <= days_threshold:
                if issue:
                    print(f"Issue already exists for {domain} (WHOIS)")
                else:
                    create_issue(
                        repo,
                        f"⚠️ Domain {domain} expires in {days_left} days!",
                        f"**{domain}** will expire on {exp_date:%Y-%m-%d}.\nDays left: {days_left}"
                    )
            else:
                if issue:
                    close_issue(issue, f"✅ Domain {domain} renewed (expires {exp_date:%Y-%m-%d}, {days_left} days left).")
                else:
                    print(f"{domain}: WHOIS OK ({days_left} days left)")

        # ---- SSL Expiration ----
        ssl_exp = get_ssl_expiration(domain)
        if ssl_exp:
            ssl_days = (ssl_exp - datetime.now()).days
            issue = find_issue(repo, f"SSL {domain}")
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
                else:
                    print(f"{domain}: SSL OK ({ssl_days} days left)")

        # ---- HTTP Status ----
        status, resp_time = get_http_status(domain)
        issue = find_issue(repo, f"Status {domain}")

        # Check for HTTP errors
        if status is None or status >= 400:
            if not issue:
                create_issue(
                    repo,
                    f"❌ Status check failed for {domain}",
                    f"Latest HTTP response: `{status}`, response time: {resp_time:.0f} ms"
                )
        # Check for slow response
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
            else:
                print(f"{domain}: HTTP {status} OK, response time {resp_time:.0f} ms")

        # ---- JSON for status page ----
        domain_info = {
            "domain": domain,
            "whois_expiry": exp_date.strftime("%Y-%m-%d") if exp_date else None,
            "whois_ok": days_left > days_threshold if exp_date else False,
            "ssl_expiry": ssl_exp.strftime("%Y-%m-%d") if ssl_exp else None,
            "ssl_ok": ssl_days > days_threshold if ssl_exp else False,
            "http_status": status,
            "http_ok": status is not None and status < 400,
            "http_response_time_ms": resp_time
        }
        results["domains"].append(domain_info)


        #save per domain
        domain_file = f"status/{domain}.json"
        domain_history_folder = f"status/history/{domain}"
        os.makedirs(domain_history_folder, exist_ok=True)

        with open(domain_file, "w") as f:
            json.dump(domain_info, f, indent=2)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        history_file = f"{domain_history_folder}/status_{timestamp}.json"
        with open(history_file, "w") as f:
            json.dump(domain_info, f, indent=2)

    # ---- JSON Status page ----
    os.makedirs("status", exist_ok=True)
    with open("status/status.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
