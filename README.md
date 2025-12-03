Easily monitor your domains and get alerts when:

* ⏳ domain is set to expire within **30 days**
* 🔒 domain SSL certificate **expires soon**
* ⚠️ HTTP status code for website is **>400**
* 🚨 IP address for the website changes

relies entirely on **GitHub Actions** and **GitHub Issues**—no external services required.

---

## Demo

For demo view: [http://status.pejcic.rs/status/](http://status.pejcic.rs/status/)

<table border="0">
 <tr>
    <td><b style="font-size:30px">All monitors</b></td>
    <td><b style="font-size:30px">Single page</b></td>
 </tr>
 <tr>
    <td><a href="http://status.pejcic.rs/status/"><img src="https://github.com/user-attachments/assets/b0b98526-d5b4-4a9d-9f94-526e93147707" width="400" /></a></td>
    <td><a href="https://status.pejcic.rs/status/domain.html?domain=openpanel.com"><img src="https://github.com/user-attachments/assets/9ca1d2bb-5c3a-47ef-aabb-666a375ccae5" width="400" /></a></td>
 </tr>
</table>

---
## 🚀 Usage

1. Fork repository
2. Add your domains to `domains.txt`.
3. Optional: If you want a status page, create Gitub Page
4. That’s it—no extra configuration needed.

The workflow will:

* Run automatically **almost every mininute** (or you can trigger it manually).
* Check the expiration dates of your listed domains.

<table border="0">
 <tr>
    <td>If a domain expires soon, IP changes, SSL expired or status code is >400, a GitHub issue will be opened: </td>
    <td>If the domain is later renewed, SSL renewed or status code changes, the issue will be <b>automatically closed</b>:</td>
 </tr>
 <tr>
    <td><br>
     <img width="400" alt="image" src="https://github.com/user-attachments/assets/f9c53697-15c6-4c46-9ef3-00e663f62e7d" /></td>
    <td>
     <img width="400" alt="image" src="https://github.com/user-attachments/assets/14fe1bcd-068f-4ecb-b2ff-f1e568708ce1" /></td>
 </tr>
</table>
  


## TODO
- ~detect nameserver changes and open issues~
- ~add ignore option for ip changes when cloudflare proxy is used~
- ~add ignore option for ip changes when vercel is used~
- record whois data
- create screenshot when response code >400
- tag in comment or auto-assign isuses
- setup assigments per domain
- if multiple domains (sub dir or domain) of same domain, reuse existing whois data
- implement https://raw.githubusercontent.com/stefanpejcic/vercel-ipv4/refs/heads/main/list.txt
- 
implement 
