import time
from scapy.all import sniff,IP,TCP,ICMP,Raw, get_working_ifaces
import socket
import requests
import ipaddress
from update_whitelist import update_whitelist
import re
from urllib.parse import urlparse
#Configuratia de baza
LOG_FILE = "network_log.txt"
PORT_SCAN_THRESHOLD = 20 #cate porturi un ip are voie sa atinga inainte de alerta
PORT_ICMP=5 #cate pachete ICMP un ip are voie sa atinga inainte de alerta
SQLI_SIGNATURES = [                      
    r"union(\s+|\+|%20)select",                   # Detectează UNION SELECT cu spațiu, + sau %20
    r"select(\s+|\+|%20).+from",                  # Detectează SELECT ... FROM
    r"insert(\s+|\+|%20)into",                    # Detectează INSERT INTO
    r"drop(\s+|\+|%20)table",                     # Detectează DROP TABLE
    r"or(\s+|\+|%20)\d+=\d+",                     # Detectează OR 1=1, or+1=1, or%201=1
    r"or(\s+|\+|%20)\d+%3d\d+",                   # Detectează când egalul devine %3D (or+1%3D1)
    r"--"                                         # Detectează simplu comentariul SQL, chiar dacă e la finalul liniei
]
XSS_SIGNATURES=[
    r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",  # Detectează tag-uri script
    r"on\w+\s*=\s*(['\"]?).*?\1",                        # Detectează atribute on* (ex: onclick, onerror)
    r"javascript:",                                      # Detectează schemele javascript:
    r"document\.cookie",                                  # Detectează accesul la cookie-uri
    r"window\.location",                                  # Detectează manipularea locației
    r"iframe.*?",
    r"alert\s*\(",                                        # Detectează funcția alert() în JavaScript
]
ALERTE_RECENTE={}
EXPIRARE_ALERTE=10
DOS_PACKET_THRESHOLD=30 #cate pachete pe secunda are voie un ip sa trimita catre portul tinta inainte de alerta
dos_traffic_history={}
whitelist_memorie = set()
icmp_history = {}
network_history = {}
ultima_actualizare=time.time()
ULTIMA_CURATARE_GLOBALA    = time.time()
def write_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    alert_line= f"{timestamp} - ALERT: {message}\n"
    print(f"[ALERTA]  {alert_line.strip()}")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(alert_line)
def analyze_packet(packet):
    acum=time.time()
    global ip_tailscale
    global ultima_actualizare
    global DOS_PACKET_THRESHOLD
    global dos_traffic_history
    global ULTIMA_CURATARE_GLOBALA
    if acum - ultima_actualizare > 3600*24: #actualizez whitelist-ul 
        update_whitelist()
        incarcare_whitelist_in_memorie()
        ultima_actualizare = acum
    if not packet.haslayer(IP):
        return
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst 
    if verifica_ip_in_whitelist(src_ip) or verifica_ip_in_whitelist(dst_ip):
        return

    if src_ip not in dos_traffic_history:
            dos_traffic_history[src_ip] = []
                # Curățăm pachetele mai vechi de 3 secundă din istoric
    dos_traffic_history[src_ip] = [t for t in dos_traffic_history[src_ip] if acum - t < 3]
                # Adăugăm timestamp-ul pachetului curent
    dos_traffic_history[src_ip].append(acum)
                     # Dacă IP-ul a trimis mai multe pachete decât pragul maxim 
    if len(dos_traffic_history[src_ip]) > DOS_PACKET_THRESHOLD:
            cheie_alerta_dos = (src_ip, "GLOBAL_DOS")
            if cheie_alerta_dos not in ALERTE_RECENTE or (acum - ALERTE_RECENTE[cheie_alerta_dos]) > 5:
                ALERTE_RECENTE[cheie_alerta_dos] = acum
                write_alert(f"RATE-LIMIT DOS DETECTED: {src_ip} a trimis {len(dos_traffic_history[src_ip])} pachete/secunda catre {dst_ip}!")
                return
    if acum - ULTIMA_CURATARE_GLOBALA > 3600: #curat istoric dos la fiecare ora
        for t in dos_traffic_history:
            dos_traffic_history[t] = [timestamp for timestamp in dos_traffic_history[t] if acum - timestamp < 3]
        ULTIMA_CURATARE_GLOBALA = acum
    if packet.haslayer(TCP):#caut in layer TCP
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        if dst_port != 5000:
            return
        acum = time.time()
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            if any(metoda in payload for metoda in ["get ","delete ","post ", "put "]):
                for signature in XSS_SIGNATURES:
                    if re.search(signature, payload):
                        write_alert(f"Posibil atac XSS de la {src_ip} catre {dst_ip} pe portul {dst_port}")
                        return
                for signature in SQLI_SIGNATURES:
                    if re.search(signature, payload):
                        cheie_alerta=(src_ip,signature)
                        timp_curent=time.time()
                        if cheie_alerta in ALERTE_RECENTE and (timp_curent - ALERTE_RECENTE[cheie_alerta]) < EXPIRARE_ALERTE:
                            return 
                        ALERTE_RECENTE[cheie_alerta]=timp_curent
                        write_alert(f"Posibil atac SQL Injection de la {src_ip} catre {dst_ip} pe portul {dst_port}")
                        return
            payload_raw = packet[Raw].load.decode('utf-8', errors='ignore')
            
            match_host = re.search(r'(?i)host:\s*([^\r\n]+)', payload_raw)
            match_origin = re.search(r'(?i)origin:\s*([^\r\n]+)', payload_raw)
            match_referer = re.search(r'(?i)referer:\s*([^\r\n]+)', payload_raw)
            match_fetch_site = re.search(r'(?i)sec-fetch-site:\s*([^\r\n]+)', payload_raw)
            
            if match_host:
                host_target = match_host.group(1).strip().lower().split(':')[0]
                
                # 1. Detecție bazată pe Sec-Fetch-Site (Standard modern foarte stabil)
                if match_fetch_site:
                    fetch_site_value = match_fetch_site.group(1).strip().lower()
                    # Daca cererea e catre o metoda sensibila si vine de pe alt site
                    if fetch_site_value == "cross-site" and any(m in payload for m in ["post ", "put ", "delete "]):
                        write_alert(f"CSRF DETECTAT (Sec-Fetch-Site: cross-site) de la {src_ip} -> {dst_ip}")
                        return

                # 2. Detecție bazată pe Origin
                if match_origin:
                    origin_value = match_origin.group(1).strip().lower()
                    if origin_value == "null":
                        write_alert(f"Posibil atac CSRF cu Origin null de la {src_ip} catre {dst_ip}")
                        return
                    
                    # Extrage domeniul/IP-ul curat din Origin (ex: din http://atacator.com scoate atacator.com)
                    origin_domain = urlparse(origin_value).netloc.split(':')[0] if "://" in origin_value else origin_value
                    
                    if host_target not in origin_domain and origin_domain != "":
                        write_alert(f"Atac CSRF detectat! Origin diferit de Host ({origin_value} -> {host_target})")
                        return

                # 3. Detecție bazată pe Referer (Speranța de bază pentru request-uri clasice)
                if match_referer:
                    referer_value = match_referer.group(1).strip().lower()
                    
                    # Extrage domeniul/IP-ul curat din Referer
                    referer_domain = urlparse(referer_value).netloc.split(':')[0] if "://" in referer_value else referer_value
                    
                    if host_target not in referer_domain and referer_domain != "":
                        write_alert(f"Atac CSRF detectat! Referer extern suspect ({referer_value} -> {host_target})")
                        return

    
ip_tailscale=None
##=porneste ids=##        
def porneste_ids():
    global ultima_actualizare
    global ip_tailscale
    print("[*] Pornire ids ......")
    try:
        print("[*] Generare inițială whitelist...")
        update_whitelist()
        ultima_actualizare = time.time() 
    except Exception as e:
        print(f"[WARN] Nu s-a putut genera whitelist-ul la start: {e}")
    incarcare_whitelist_in_memorie()
    # --- DETECTARE AUTOMATĂ INTERFAȚĂ TAILSCALE ---
    interfata_ids = None
    toate_interfetele = get_working_ifaces()
    
    for iface in toate_interfetele:
        # Tailscale folosește mereu IP-uri care încep cu "100." (clasa 100.64.0.0/10)
        if iface.ip and iface.ip.startswith("100."):
            interfata_ids = iface.name # Acesta va fi codul de tip \Device\NPF_...
            ip_tailscale = iface.ip
            print(f"[+] Am detectat interfața Tailscale: {iface.description} ({iface.ip})")
            break
            
    if not interfata_ids:
        # Dacă nu găsește Tailscale, punem ca fallback Loopback (pentru teste locale)
        print("[WARN] Nu s-a găsit nicio interfață Tailscale activă. Folosesc Loopback ca fallback.")
        interfata_ids = "\\Device\\NPF_Loopback"
    # ----------------------------------------------

    print(f"[*] IDS-ul ascultă pe: {interfata_ids} pe portul 5000...")
    
    # Pornim sniff-ul cu filtrul setat strict pe portul 5000 al aplicației Flask
    sniff(iface=interfata_ids, filter="tcp port 5000", prn=analyze_packet, store=0)
def verifica_ip_in_whitelist(ip):
    try:
            return any(ipaddress.ip_address(ip) in ipaddress.ip_network(entry) for entry in whitelist_memorie )
    except Exception as e:
        print(f"[ERROR] Eroare la verificarea IP-ului in whitelist: {e}")
        return False
def incarcare_whitelist_in_memorie():
    global whitelist_memorie
    try:
        with open("whitelist.txt", "r") as whitelist_file:
            whitelist_memorie = set(line.strip() for line in whitelist_file)
            return whitelist_memorie
    except Exception as e:
        print(f"[ERROR] Eroare la incarcarea whitelist-ului in memorie: {e}")
        return set()
