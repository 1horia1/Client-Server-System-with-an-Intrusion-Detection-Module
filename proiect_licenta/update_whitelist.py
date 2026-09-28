import ipaddress
import requests
import socket 
def update_whitelist():
    print("[*] Actualizare whitelist ......")
    #google
    ip_noi=set()
    try:
        url_google = "https://www.gstatic.com/ipranges/goog.json"
        response_google = requests.get(url_google)
        if response_google.status_code == 200:
            data_google = response_google.json()
            for prefix in data_google.get("prefixes", []):
                if "ipv4Prefix" in prefix:
                    ip_noi.add(prefix["ipv4Prefix"])
                elif "ipv6Prefix" in prefix:
                    ip_noi.add(prefix["ipv6Prefix"])
    except Exception as e:
        print(f"[ERROR] Eroare la actualizarea whitelist-ului google: {e}")
    #amazon
    try:
        url_aws = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        response_aws = requests.get(url_aws)
        if response_aws.status_code == 200:
            for prefix in response_aws.json().get("prefixes", []):
                if "ip_prefix" in prefix:
                    ip_noi.add(prefix["ip_prefix"])
    except Exception as e:
        print(f"[ERROR] Eroare la actualizarea whitelist-ului amazon: {e}")
    #azure
    # 3. MICROSOFT, AZURE & WINDOWS UPDATE (API-ul Oficial - 100% Automat)
    try:
        # Acesta este endpoint-ul XML/JSON public global pus la dispoziție de Microsoft
        url_ms = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
        response_ms = requests.get(url_ms, timeout=5)
        if response_ms.status_code == 200:
            data_ms = response_ms.json()
            for item in data_ms:
                # Extragem listele de rețele (ips) din fiecare serviciu Microsoft detectat
                if "ips" in item:
                    for ip_cidr in item["ips"]:
                        # Filtrăm doar IPv4 ca să fie mai ușor de procesat pentru IDS, dar le poți lăsa pe toate
                        if ":" not in ip_cidr: 
                            ip_noi.add(ip_cidr)
            print("[+] Am descărcat automat rețelele oficiale Microsoft/Azure.")
    except Exception as e:
        print(f"[ERROR] Eroare la descărcarea automată a IP-urilor Microsoft: {e}")
    #meta
    domenii_meta = ["github.com","api.github.com","facebook.com", "instagram.com", "whatsapp.com", "meta.com","go.microsoft.com","microsoft.com","ntservicepack.microsoft.com","dl.delivery.mp.microsoft.com","download.microsoft.com","download.windowsupdate.com", "office.com", "azure.com", "windows.net", "visualstudio.com"]
    for domeniu in domenii_meta:
            try:
                ip_addresses = socket.gethostbyname_ex(domeniu)[2]
                for ip in ip_addresses:
                     ip_noi.add(f"{ip}/32")
            except Exception as e:
                print(f"[ERROR] Eroare la actualizarea whitelist-ului {domeniu}  : {e}")
    #salvez in whitelist
    if not ip_noi:
        print("[*] Nu s-au gasit IP-uri noi pentru whitelist.")
        return
    else:
        try:
            with open("whitelist.txt", "w") as whitelist_file:
                for ip in ip_noi:
                    whitelist_file.write(f"{ip}\n")
            print(f"Whitelist actualizata cu {len(ip_noi)} IP-uri.")
        except Exception as e:
            print(f"[ERROR] Eroare la salvarea whitelist-ului: {e}")
