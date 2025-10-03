import whois
from datetime import datetime, timedelta
from github import Github
import os

DOMAINS_FILE = "domains.txt"
DAYS_THRESHOLD = 30

def read_domains(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_expiration(domain):
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):  # sometimes it's a list
            exp = exp[0]
        return exp
    except Exception as e:
        print(f"Error checking {domain}: {e}")
        return None

def create_issue(repo, domain, exp_date, days_left):
    title = f"⚠️ Domain {domain} expires in {days_left} days!"
    body = f"""
The domain **{domain}** will expire on **{exp_date.strftime('%Y-%m-%d')}**.

⏰ Days left: **{days_left}**

Please renew it ASAP.
"""
    existing_issues = repo.get_issues(state="open")
    for issue in existing_issues:
        if domain in issue.title:
            print(f"Issue already exists for {domain}")
            return
    repo.create_issue(title=title, body=body)
    print(f"Issue created for {domain}")

def main():
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")  # GitHub Actions provides this
    g = Github(token)
    repo = g.get_repo(repo_name)

    domains = read_domains(DOMAINS_FILE)
    for domain in domains:
        exp_date = get_expiration(domain)
        if not exp_date:
            continue
        days_left = (exp_date - datetime.now()).days
        if days_left <= DAYS_THRESHOLD:
            create_issue(repo, domain, exp_date, days_left)
        else:
            print(f"{domain}: {days_left} days left (OK)")

if __name__ == "__main__":
    main()
