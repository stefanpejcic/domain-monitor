<!--start: description-->

**🗿 Heimdall** is an open-source WHOIS, DNS, Uptime monitor and status page, fully powered by GitHub Actions and GitHub Pages.

<details data-embed="https://github.com/stefanpejcic/heimdall/" data-title="Heimdall" data-summary="an open-source WHOIS, DNS, Uptime monitor and status page, fully powered by GitHub Actions and GitHub Pages">
  <summary>Why Heimdall?</summary>

In the summer of 2025, I got caught up with personal milestones: got married, became a father, bought an apartment - and **ended up missing domain expiration emails**. Several of my domains, including [pcx3.com](https://web.archive.org/web/20250617005754/https://pcx3.com/) and [plugins.club](https://web.archive.org/web/20250418220804/http://plugins.club/), expired, and years of work and projects were lost. 😞 I didn't want this to ever happen again, neither to me nor anyone else.

Since I use GitHub daily, I realized that if these were GitHub Issues, I probably wouldn't have missed them.

That's why I decided to use [Upptime](https://github.com/upptime/upptime), an amazing tool that tracks uptime using GitHub Issues. However, I wasn't a fan of how it records statuses via git commits. I wanted JSON data that could easily feed into other tools like Grafana.

Enter **Heimdall**: it uses GitHub Actions to run scheduled checks, stores results in JSON files per domain, and presents the data on a front-end using simple HTML pages.

It notifies you whenever there are changes to your domain's WHOIS info, SSL certificate, or HTTP status/response.

Feel free to use it, experiment, break it, fork it - whatever you like!

---
</details>

<!--end: description-->

Easily monitor your domains and get alerts when:

* ⏳ Domain (WHOIS) is set to expire within **30 days**
* 🔓 SSL certificate **expires soon** _([example](https://github.com/stefanpejcic/heimdall/issues/410))_
* ⚠️ HTTP status code for website is **>400** _([example](https://github.com/stefanpejcic/heimdall/issues/1432))_
* 🐌 Response time for website is **>1000ms** _([example](https://github.com/stefanpejcic/heimdall/issues/1433))_
* 🚨 IP address (A record) for domain changes _([example](https://github.com/stefanpejcic/heimdall/issues/1372))_
* 🚨 Nameservers for the domain are changed

relies entirely on **GitHub Actions** and **GitHub Issues** - no external services required.

---

## Demo

For live demo view: [http://status.pejcic.rs/status/](http://status.pejcic.rs/status/)

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
4. That's it.

The workflow will:

* Run automatically **almost every mininute** (or you can trigger it manually).
* Check daily: WHOIS expiration date, SSL expiration date, Nameservers.
* Check every time: A record, HTTP response time, Status code.

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
- ~detect registrar changes in whois info~
- record whois data
- check A, AAAA, MX, SOA, TXT records
- create screenshot when response code >400
- tag in comment or auto-assign isuses
- setup assigments per domain
- if multiple domains (sub dir or domain) of same domain, reuse existing whois data
- implement https://raw.githubusercontent.com/stefanpejcic/vercel-ipv4/refs/heads/main/list.txt
- 
implement 
