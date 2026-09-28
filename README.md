# Client-Server System with an Intrusion Detection Module

This repository contains the source code for the bachelor's thesis titled **"Client-Server System with an Intrusion Detection Module"**, developed at the University of Bucharest, Faculty of Mathematics and Computer Science, Computer Science specialization.

---

## 📋 Overview

The project implements a secure and monitored client-server environment consisting of:
1. **A Vulnerable Web Platform (Flask Application):** A company ticket management system featuring role-based access control (User and Manager) and intentionally integrated vulnerabilities for educational and testing purposes (SQL Injection, XSS, CSRF, DoS, Broken Access Control, and Information Disclosure).
2. **A Custom Intrusion Detection System (NIDS):** A signature-based Network Intrusion Detection System developed manually in Python using regular expressions, intercepting real-time network traffic to identify cyber attacks.
3. **Distributed Testing Environment:** System validation was performed using two physical workstations and a virtual machine (Kali Linux), interconnected via a secure mesh VPN tunnel powered by **Tailscale**.

---

## 🛠️ Technologies Used

* **Backend / Web Framework:** Python, Flask
* **Database:** SQLite3
* **Network Security & IDS:** Scapy (for packet interception)
* **Networking / Communication:** Tailscale (Mesh VPN)
* **Other Tools:** Custom Python attack simulation scripts and dynamic whitelist generation mechanisms.

---

## ⚙️ Project Architecture

* **Web Module (Flask):** Handles ticketing logic, user sessions, secure/vulnerable routes, and a comprehensive **Audit Log** system accessible exclusively by managers.
* **IDS Module (NIDS):** 
  * Automatically builds a dynamic whitelist updated periodically to eliminate false-positive alerts originating from major providers (Google, Amazon, Microsoft, etc.).
  * Monitors traffic on the dedicated interface and inspects network layers (specifically the `Raw` layer via Regex) for attack signatures.
  * Implements RAM optimization algorithms (automatic cleanup of state dictionaries and setting `store=0` in Scapy).

---

## 🔒 Simulated Attacks & Detection

The system was tested against the following threat vectors:
* **Denial of Service (DoS):** Generating multiple concurrent requests with resource-heavy SQL queries; the IDS monitors request frequency per source IP.
* **SQL Injection (SQLi):** Manipulating queries in the search bar to bypass access controls or extract data.
* **Cross-Site Scripting (XSS Stored):** Injecting malicious scripts into ticket descriptions.
* **Cross-Site Request Forgery (CSRF):** Forcing managers to execute unauthorized actions (ticket deletion) via hidden forms on external sites.
* **Broken Access Control (IDOR) & Information Disclosure:** Exploiting object reference flaws and detailed error messages.

---

## 🚀 Getting Started (General Instructions)


Install dependencies:
Make sure Python is installed, then run:



```Bash
pip install flask scapy user-agents werkzeug
```
Initialize the database (if needed):

```Bash
flask --app app init-db
```
Run the application:
(Starting app.py will automatically launch the Flask web server and spin up the background IDS thread).
Configure network accessibility (Tailscale):
If you are running the application across multiple machines connected via Tailscale, make sure to bind the Flask server and the IDS monitoring interface correctly to your Tailscale IP address (or run it publicly on 0.0.0.0 over the Tailscale secure interface so that the testing machine/attacker workstation can properly reach it and generate traffic).
```Bash
python app.py
```


## 🎯 How to Launch Attacks Against the Platform
To test the IDS detection capabilities and application vulnerabilities, attacks can be performed through the following vectors:

1. **SQL Injection (SQLi) & Information Disclosure**:

On Login: Input a single quote or special characters in the email field. The vulnerable query `(SELECT * FROM users WHERE email = '{email}')` will throw an unhandled database exception. The application catches this and returns a JSON response leaking internal server paths, Python version, and database type.

On Ticket Search: Use the search bar `(/tickets/search?q=...)` with payloads like `'` OR `1=1 --` to bypass ownership filters and extract records belonging to other users.

2. **Stored Cross-Site Scripting (XSS)**:

Create or edit a ticket description by injecting HTML/JavaScript payload tags, such as:

HTML
```bash
<script>
window.location.href = "[https://www.youtube.com/watch?v=dQw4w9WgXcQ](https://www.youtube.com/watch?v=dQw4w9WgXcQ)";
</script>
```

Because the template uses the | safe filter, the script will execute directly in the browser when viewed.

3. **Cross-Site Request Forgery (CSRF)**:

Set up an external malicious page containing a hidden POST form targeting the manager route `/tickets/delete/<target_id>`. When an authenticated manager visits the external page, their browser automatically appends the active session cookies, executing an unauthorized deletion.

4. **Denial of Service (DoS)**:

Launch concurrent multi-threaded scripts (e.g., 100 threads) sending repeated search queries combined with resource-intensive SQLite payloads (such as `zeroblob(100000000)`) to exhaust server memory and processing power while the IDS tracks request frequencies per source IP.

5. **Broken Access Control (IDOR)**:

Log in as a regular user and manually modify the ticket ID in the browser URL (e.g., `/tickets/view/<ID>`) to access and view arbitrary tickets belonging to other users without authorization checks.

## 📄 License
This project was developed for educational purposes as part of a bachelor's thesis. Please refer to the LICENSE file for details regarding terms of use.
