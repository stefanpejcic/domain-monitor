import whois
from datetime import datetime
from github import Github, Auth
import os

DOMAINS_FILE = "domains.txt"

def read_domains(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_expiration(domain):
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        return exp
    except Exception as e:
        print(f"Error checking {domain}: {e}")
        return None

def find_issue(repo, domain):
    """Check if an open issue already exists for this domain."""
    issues = repo.get_issues(state="open")
    for issue in issues:
        if domain in issue.title:
            return issue
    return None

def create_issue(repo, domain, exp_date, days_left):
    title = f"⚠️ Domain {domain} expires in {days_left} days!"
    body = f"""
The domain **{domain}** will expire on **{exp_date.strftime('%Y-%m-%d')}**.

⏰ Days left: **{days_left}**

Please renew it ASAP.
"""
    repo.create_issue(title=title, body=body)
    print(f"Issue created for {domain}")

def close_issue(issue, domain, exp_date, days_left):
    msg = f"✅ Domain {domain} has been renewed. Expiration: {exp_date.strftime('%Y-%m-%d')} ({days_left} days left). Closing this issue."
    issue.create_comment(msg)
    issue.edit(state="closed")
    print(f"Issue closed for {domain}")

def main():
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")
    days_threshold = int(os.getenv("DAYS_THRESHOLD", "30"))

    g = Github(auth=Auth.Token(token))
    repo = g.get_repo(repo_name)

    domains = read_domains(DOMAINS_FILE)
    for domain in domains:
        exp_date = get_expiration(domain)
        if not exp_date:
            continue
        days_left = (exp_date - datetime.now()).days
        issue = find_issue(repo, domain)

        if days_left <= days_threshold:
            if issue:
                print(f"Issue already exists for {domain}")
            else:
                create_issue(repo, domain, exp_date, days_left)
        else:
            if issue:
                close_issue(issue, domain, exp_date, days_left)
            else:
                print(f"{domain}: {days_left} days left (OK, no issue needed)")

if __name__ == "__main__":
    main()
