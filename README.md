Easily monitor your domains and get alerts when:

* ⏳ domain is set to expire within **30 days**
* 🔒 domain SSL certificate **expires soon**
* ⚠️ HTTP status code for website is **>400**

relies entirely on **GitHub Actions** and **GitHub Issues**—no external services required.

<img width="807" height="393" alt="image" src="https://github.com/user-attachments/assets/f9c53697-15c6-4c46-9ef3-00e663f62e7d" />  

---

## Demo

For demo view: [http://status.pejcic.rs/status/](http://status.pejcic.rs/status/)

---
## 🚀 Usage

1. Fork repository
2. Add your domains to `domains.txt`.
3. That’s it—no extra configuration needed.

The workflow will:

* Run automatically **once per day** (or you can trigger it manually).
* Check the expiration dates of your listed domains.
* If a domain expires soon, SSL expired or status code is >400, a GitHub issue will be opened:

<img width="997" height="576" alt="image" src="https://github.com/user-attachments/assets/72823c59-20bb-4b74-8b1e-4d8b17085beb" />  

* If the domain is later renewed, SSL renewed or status code changes, the issue will be **automatically closed**:

<img width="997" height="576" alt="image" src="https://github.com/user-attachments/assets/14fe1bcd-068f-4ecb-b2ff-f1e568708ce1" />  
