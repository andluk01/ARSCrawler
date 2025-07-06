#source venv_mpl/bin/activate

import re
from collections import defaultdict
from datetime import datetime
import json
from abuse_check import controlla_ip_abuseipdb
import random
from queue import Queue
from threading import Thread
import matplotlib.pyplot as plt
import sys
import os
import threading
import time
import ipaddress
import socket
import geoip2.database
import time
import urllib.request
import configparser
import io


def carica_configurazione(percorso_file="configurazione.conf"):
    config = configparser.ConfigParser()
    config.read(percorso_file)

    # Percorsi
    log_file = config["percorsi"]["log_file"]
    CDN_PATH = config["percorsi"]["cdn_path"]
    CRAWLER_FILE = config["percorsi"]["crawler_file"]
    COUNTRY_DB = config["percorsi"]["country_db"]
    ASN_DB = config["percorsi"]["asn_db"]
    WHITELIST_DB = config["percorsi"]["whitelist_db"]
    PROVIDERS_KEYWORDS = config["percorsi"]["providers_keywords"]
    NAZIONI_BLOCCATE = config["percorsi"]["nazioni_bloccate"]

    # Soglie di classificazione
    LOGIN_SOSPETTO = int(config["classificazione"]["login_soglia_sospetto"])
    LOGIN_MALEVOLO = int(config["classificazione"]["login_soglia_malevolo"])
    POST_SOSPETTO = int(config["classificazione"]["post_soglia_sospetto"])
    POST_MALEVOLO = int(config["classificazione"]["post_soglia_malevolo"])
    FREQ_LEGITTIMO = float(config["classificazione"]["frequenza_legittimo"])
    FREQ_ILLEGITTIMO = float(config["classificazione"]["frequenza_illegittimo"])
    ERROR_SOSPETTO = int(config["classificazione"]["error_4xx_soglia_sospetto"])
    ERROR_MALEVOLO = int(config["classificazione"]["error_4xx_soglia_malevolo"])

    # Generale
    FINESTRA_DEFAULT = int(config["generale"]["finestra_default"])

    return {
        "percorsi": {
            "log_file": log_file,
            "cdn_db": CDN_PATH,
            "crawler_db": CRAWLER_FILE,
            "country_db": COUNTRY_DB,
            "asn_db": ASN_DB,
            "whitelist_db": WHITELIST_DB,
            "providers_keywords": PROVIDERS_KEYWORDS,
            "nazioni_bloccate": NAZIONI_BLOCCATE,
        },
        "soglie": {
            "login_sospetto": LOGIN_SOSPETTO,
            "login_malevolo": LOGIN_MALEVOLO,
            "post_sospetto": POST_SOSPETTO,
            "post_malevolo": POST_MALEVOLO,
            "frequenza_legittimo": FREQ_LEGITTIMO,
            "frequenza_illegittimo": FREQ_ILLEGITTIMO,
            "error_sospetto": ERROR_SOSPETTO,
            "error_malevolo": ERROR_MALEVOLO,
        },
        "generale": {
            "finestra_default": FINESTRA_DEFAULT
        }
    }
config = carica_configurazione()



# Percorsi file
log_file = config["percorsi"]["log_file"]
CDN_PATH = config["percorsi"]["cdn_db"]
CRAWLER_FILE = config["percorsi"]["crawler_db"]
COUNTRY_DB = config["percorsi"]["country_db"]
ASN_DB = config["percorsi"]["asn_db"]
WHITELIST_DB = config["percorsi"]["whitelist_db"]
PROVIDERS_KEYWORDS = config["percorsi"]["providers_keywords"]
NAZIONI_BLOCCATE = config["percorsi"]["nazioni_bloccate"]

# Soglie di classificazione
LOGIN_SOGLIA_SOSPETTO = config["soglie"]["login_sospetto"]
LOGIN_SOGLIA_MALEVOLO = config["soglie"]["login_malevolo"]
POST_SOGLIA_SOSPETTO = config["soglie"]["post_sospetto"]
POST_SOGLIA_MALEVOLO = config["soglie"]["post_malevolo"]
FREQ_SOGLIA_LEGITTIMO = config["soglie"]["frequenza_legittimo"]
FREQ_SOGLIA_ILLEGITTIMO = config["soglie"]["frequenza_illegittimo"]
ERROR_4XX_SOGLIA_SOSPETTO = config["soglie"]["error_sospetto"]
ERROR_4XX_SOGLIA_MALEVOLO = config["soglie"]["error_malevolo"]

# Parametri generali
FINESTRA_DEFAULT = config["generale"]["finestra_default"]


os.makedirs("output", exist_ok=True)  # crea la cartella se non esiste

sys.stdout = open("output/output.txt", "w", encoding="utf-8")
sys.stderr = sys.stdout


enrichment_cache = {}

def is_hosting_provider(asn_or_ptr):
    lowered = asn_or_ptr.lower()
    return any(provider in lowered for provider in CLOUD_PROVIDERS_KEYWORDS)


# Apri i database una sola volta (in cima al file o in __main__)
reader_country = geoip2.database.Reader(COUNTRY_DB)
reader_asn = geoip2.database.Reader(ASN_DB)

def enrich_ip(ip):
    if ip in enrichment_cache:
        return enrichment_cache[ip]

    enrichment = {
        "country": "N/A",
        "asn": "N/A",
        "ptr": "N/A"
    }

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        enrichment["ptr"] = hostname
    except Exception:
        pass

    try:
        response = reader_country.country(ip)
        enrichment["country"] = response.country.iso_code
    except Exception:
        pass

    try:
        response = reader_asn.asn(ip)
        enrichment["asn"] = f"AS{response.autonomous_system_number} {response.autonomous_system_organization}"
    except Exception:
        pass

    enrichment_cache[ip] = enrichment  # cache the result
    return enrichment

#carico le nazioni che devono essere blocate
def carica_nazioni_bloccate(percorso_file):
    nazioni = set()
    try:
        with open(percorso_file, "r", encoding="utf-8") as f:
            for line in f:
                code = line.strip().upper()
                if code:
                    nazioni.add(code)
    except FileNotFoundError:
        print(f"[WARNING] File {percorso_file} non trovato. Nessuna nazione sarà bloccata.")
    return nazioni

NAZIONI_BLOCCATE = carica_nazioni_bloccate(NAZIONI_BLOCCATE)


#carico le parole chiavi per identificare crawler
def load_crawler_keywords(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Attenzione: file '{file_path}' non trovato.")
        return []

CRAWLER_KEYWORDS = load_crawler_keywords(CRAWLER_FILE)

def carica_keyword_cloud(path_file):
    keywords = []
    with open(path_file, "r", encoding="utf-8") as f:
        for line in f:
            keyword = line.strip()
            if keyword and not keyword.startswith("#"):
                keywords.append(keyword.lower())
    return keywords

CLOUD_PROVIDERS_KEYWORDS = carica_keyword_cloud(PROVIDERS_KEYWORDS)

#carico indirizzi noti per identificare crawler
def load_ip_whitelist(file_path):
    try:
        with open(file_path, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"[ERROR] Attenzione: file '{file_path}' non trovato.")
        return set()

WHITELIST_IPS = load_ip_whitelist(WHITELIST_DB)

def load_cdn_ranges(file_path):
    cdn_ranges = {}
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    cdn_name, ip_range = line.split()
                    net = ipaddress.ip_network(ip_range)
                    cdn_ranges.setdefault(cdn_name.lower(), []).append(net)
                except ValueError:
                    print(f"[ERROR] Riga non valida nel file CDN: {line}")
    except FileNotFoundError:
        print(f"[ERROR] File dei range CDN non trovato: {file_path}")
    return cdn_ranges


CDN_RANGES = load_cdn_ranges(CDN_PATH)

#controllo se ip appartiene a CDN
def identify_cdn_ip(ip_str, cdn_ranges):
    try:
        ip = ipaddress.ip_address(ip_str)
        for cdn_name, ranges in cdn_ranges.items():
            if any(ip in net for net in ranges):
                return cdn_name
    except ValueError:
        pass
    return None



# Estrae il nomi del crawler noti
def get_crawler_names(user_agents):
    matched = set()
    for ua in user_agents:
        ua_lower = ua.lower()
        for keyword in CRAWLER_KEYWORDS:
            if keyword in ua_lower:
                matched.add(keyword)
    return list(matched)

#Identificazione IP
def classify_ip(records):
    user_agents = set(r["user_agent"] for r in records)
    crawler_names = get_crawler_names(user_agents)
    ip = records[0]["ip"]

    if ip in WHITELIST_IPS:
        if crawler_names:
            nomi = ", ".join(sorted(crawler_names))
            return f"Crawler identificato (in whitelist): {nomi}"
        else:
            return "IP noto (whitelist)"

    if crawler_names:
        nomi = ", ".join(sorted(crawler_names))
        return f"Crawler identificato ({nomi})"

    return "Nessun Crawler noto identificato"

                


#Parsing riga di log
def parse_log_line(line):
    patterns = []

    # pattern specifico
    patterns.append(re.compile(
        r'(?P<host>[^:]+):(?P<port>\d+)\s+(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+"(?P<request>.+?)"\s+(?P<status>\d+|-)\s+(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s*(?P<duration>\d+)?\s*(?P<forwarded_for>\S+)?'
    ))

    # pattern meno specifico
    patterns.append(re.compile(
        r'(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+(?P<status>\d+|-)\s+(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    ))

    #pattern minimale
    patterns.append(re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\d+)'
    ))

    for pattern in patterns:
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            for key in ['host', 'port', 'ident', 'user', 'referer', 'user_agent', 'duration', 'forwarded_for']:
                data.setdefault(key, "-")
            return data, False

    data = parse_log_line_fallback(line)
    return data, True if data else (None, False)




# Parser avanzato tollerante
def parse_log_line_fallback(line):
    try:
        data = {
            "host": "-",
            "port": "-",
            "ip": "-",
            "ident": "-",
            "user": "-",
            "time": "-",
            "request": "-",
            "status": "-",
            "size": "-",
            "referer": "-",
            "user_agent": "-",
            "duration": "-",
            "forwarded_for": "-"
        }

        parts = line.strip().split()

        # Host:Porta
        if ':' in parts[0]:
            host, port = parts[0].split(':', 1)
            data['host'] = host
            data['port'] = port

        data['ip'] = parts[1]

        # Timestamp
        timestamp_match = re.search(r'\[([^\]]+)\]', line)
        if timestamp_match:
            data['time'] = timestamp_match.group(1)

        # Request
        request_match = re.search(r'"(GET|POST|HEAD|OPTIONS|PUT|DELETE|CONNECT|TRACE|PATCH) (.+?) (HTTP/\d\.\d)"', line)
        if request_match:
            data['request'] = f"{request_match.group(1)} {request_match.group(2)} {request_match.group(3)}"

        # Status code
        status_match = re.search(r'" (\d{3}) ', line)
        if status_match:
            data['status'] = status_match.group(1)

        # User-Agent
        user_agent_match = re.findall(r'"([^"]+)"', line)
        if len(user_agent_match) >= 2:
            data['user_agent'] = user_agent_match[-1]  # assume last quoted string is UA

        print(f"[WARNING] Riga malformata ma parzialmente letta: {line.strip()[:80]}...")
        return data

    except Exception as e:
        print(f"[WARNING] Riga completamente illeggibile: {line.strip()[:80]}... Errore: {e}")
        return None


#Formato della data
def parse_apache_time(time_str):
    return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")

#Calcolo delta tempo
def format_timedelta(td):
    total_seconds = int(td.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours}h {minutes}min {seconds}s"


#crezione statistiche per ip
def estrai_feature_per_ip(records):
    total = len(records)
    if total == 0:
        return {}

    html_count = 0
    img_count = 0
    pdf_ps_count = 0
    head_count = 0
    referer_vuoti = 0
    error_4xx = 0
    robots_requested = 0
    login_attempts = 0
    env_file_requested = 0
    unique_urls = set()
    post_count = 0

    for r in records:
        req = r["request"].lower()
        try:
            status = int(r["status"])
        except (ValueError, TypeError):
            status = 0

        method = req.split()[0] if req else ""
        url = req.split()[1] if len(req.split()) > 1 else ""

        unique_urls.add(url)

        if any(url.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif"]):
            img_count += 1
        elif url.endswith(".html") or url.endswith("/") or ".php" in url:
            html_count += 1

        if any(url.endswith(ext) for ext in [".pdf", ".ps"]):
            pdf_ps_count += 1

        if method == "head":
            head_count += 1

        if method == "post":
            post_count += 1

        if r["referer"] in ["", "-"]:
            referer_vuoti += 1

        if "robots.txt" in url:
            robots_requested = 1

        if any(keyword in url for keyword in ["/login", "/admin", "wp-login", "signin", "auth"]):
            login_attempts += 1

        if 400 <= status < 500:
            error_4xx += 1

        if "/.env" in url.lower():
            env_file_requested += 1


    html_img_ratio = html_count / img_count if img_count > 0 else float("inf")
    return {
        "clicks": total,
        "html_img_ratio": round(html_img_ratio, 2),
        "pdf_ps_percent": round(100 * pdf_ps_count / total, 2),
        "error_4xx_percent": round(100 * error_4xx / total, 2),
        "head_percent": round(100 * head_count / total, 2),
        "referer_null_percent": round(100 * referer_vuoti / total, 2),
        "robots_requested": robots_requested,
        "unique_url_count": len(unique_urls),
        "login_attempts": login_attempts,
        "post_count": post_count,
        "env_file_requested": env_file_requested
    }


#calcolo score
def calcola_crawler_score(features, req_per_sec, delta):
    score = 0
    note = []

    if features["clicks"] < 5:
        note.append("sessione troppo breve per valutazione significativa")
        return 0, note

    sessione_durata = delta.total_seconds()
    if req_per_sec > 20 and sessione_durata > 5:
        score += 5
        note.append("frequenza estrema (>20 req/sec, sessione >5s)")
    elif req_per_sec > 10 and sessione_durata > 5:
        score += 3
        note.append("frequenza alta (>10 req/sec, sessione >5s)")
    elif req_per_sec > 5 and sessione_durata > 5:
        score += 1
        note.append("frequenza sospetta (>5 req/sec, sessione >5s)")


    if features["html_img_ratio"] == float("inf"):
        score += 2
        note.append("solo HTML, nessuna immagine")
    elif features["html_img_ratio"] > 5:
        score += 1
        note.append("HTML/img alto")

    if features["referer_null_percent"] > 75:
        score += 2
        note.append("referer assenti (>75%)")
    elif features["referer_null_percent"] > 50:
        score += 1
        note.append("referer spesso assente (>50%)")

    if features["error_4xx_percent"] > 70:
        score += 2
        note.append("molti errori 4xx (>70%)")
    elif features["error_4xx_percent"] > 35:
        score += 1
        note.append("errori 4xx frequenti (>35%)")

    if req_per_sec > 0.01 and features["clicks"] > 50 and features["html_img_ratio"] > 2:
        score += 1
        note.append("molte richieste (senza asset) con frequenza sostenuta")


    if features["pdf_ps_percent"] > 10:
        score += 1
        note.append("PDF/PS richiesti")

    if features["head_percent"] > 90 and req_per_sec > 0.01:
        score += 1
        note.append("HEAD frequenti e ritmo sostenuto")

    if features["robots_requested"] == 1:
        score += 0.5
        note.append("robots.txt richiesto")

    if features["unique_url_count"] > 30:
        score += 2
        note.append("molti URL unici")
    elif features["unique_url_count"] > 5:
        score += 1
        note.append("alcuni URL unici")
    if features["login_attempts"] >= 10:
        score += 2
        note.append("molti tentativi login (possibile attacco)")
    elif features["login_attempts"] >= 1:
        score += 1
        note.append("alcuni tentativi di login")

    if features["post_count"] > 30:
        score += 2
        note.append("molti POST (possibile attacco)")
    elif features["post_count"] > 7:
        score += 1
        note.append("diversi POST sospetti")
    
    if features["env_file_requested"] > 0:
        score += 1
        note.append("tentativo accesso a file .env")
    return score, note


#genero grafico per la classificazione globale
def genera_grafico_classificazione_globale(legittimi, benigni, sospetti, illegittimi):
    out = sys.__stdout__  # forza la stampa nel terminale
    labels = [
        "Connessioni umane legittime",
        "Crawler benigni",
        "Crawler sospetti",
        "Crawler illegittimi"
    ]
    values = [legittimi, benigni, sospetti, illegittimi]
    totale = sum(values)

    if totale == 0:
        print(f"\n[WARNING] Nessun dato disponibile per generare il grafico globale.", file=out)
        return

    percentuali = [v / totale * 100 for v in values]

    plt.figure(figsize=(8, 6))
    plt.pie(percentuali, labels=labels, autopct="%1.2f%%", startangle=140)
    plt.axis("equal")
    plt.title("Distribuzione Classificazione Euristica")
    plt.tight_layout()

    filename = "./output/immaginiStatistiche/classificazione_globale.png"
    plt.savefig(filename)
    plt.close()
    print(f"\n[OUTPUT] Grafico per classificazione globale salvato in ./output/immaginiStatistiche.", file=out)

#genero grafico per confronto tra classificazione euristica e classificazione AbuseIPDB
def genera_grafico_confronto_abuseipdb(entrambi_malevoli, solo_abuseipdb, solo_euristica, entrambi):
    out = sys.__stdout__  # forza la stampa nel terminale
    labels = [
        "Malevoli per entrambi",
        "Malevolo solo per AbuseIPDB",
        "Malevolo solo per solo Euristica",
        "Legittimi per entrambi"
    ]
    values = [entrambi_malevoli, solo_abuseipdb, solo_euristica, entrambi]
    totale = sum(values)

    if totale == 0:
        print(f"\n[WARNING] Nessun dato disponibile per generare il grafico di confronto con AbuseIPDB.", file=out)
        return

    percentuali = [v / totale * 100 for v in values]
    colors = ["red", "orange", "dodgerblue", "green"]

    plt.figure(figsize=(8, 6))
    plt.pie(percentuali, labels=labels, colors=colors, autopct="%1.2f%%", startangle=140)
    plt.axis("equal")
    plt.title("Confronto Classificazione Euristica vs AbuseIPDB")
    plt.tight_layout()

    filename = "./output/immaginiStatistiche/confronto_abuseipdb.png"
    plt.savefig(filename)
    plt.close()
    print(f"\n[OUTPUT] Grafico per il confronto tra classificazione euristica e AbuseIPDB salvato in ./output/immaginiStatistiche.", file=out)


        

def stampa_statistiche_finali(totale_ip,conta_legittimi,conta_crawler_benigni,conta_crawler_sospetti,conta_crawler_illegittimi, CONTA_RICHIESTI,CONTA_MALEVOLO_AIPEURISTIC, CONTA_LEGITTIMI_AIPEURISTIC, CONTA_MALEVOLO_AIP, CONTA_MALEVOLO_RICHIESTO, CONTA_NON_MALEVOLO_DA_EURISTICA, CONTA_NON_MALEVOLO_DA_AIP,righe_parse_totali , righe_parse_fallback,conta_ip_cdn,righe_legittime, righe_benigne, righe_sospette, righe_illegittime):
    # Statistiche finali
    out = sys.__stdout__  # forza la stampa nel terminale
    print("\n\n\n[INFO] === Statistiche globali ===", file=out)
    if totale_ip > 0:
        print(f"[INFO] → Percentuale connessioni umane legittime: {round((conta_legittimi / totale_ip) * 100, 2)}%", file=out)
        print(f"[INFO] → Percentuale crawler benigni: {round((conta_crawler_benigni / totale_ip) * 100, 2)}%", file=out)
        print(f"[INFO] → Percentuale crawler sospetti (non noti o aggressivi): {round((conta_crawler_sospetti / totale_ip) * 100, 2)}%", file=out)
        print(f"[INFO] → Percentuale crawler illegittimi: {round((conta_crawler_illegittimi / totale_ip) * 100, 2)}%", file=out)
        print(f"[INFO] → Percentuale di ip riconosciuti appartenenti a CDN: {round((conta_ip_cdn/ totale_ip) * 100, 2)}%", file=out)
        print(f"[INFO] → Numero di ip riconosciuti appartenenti a CDN: {conta_ip_cdn}", file=out)

        somma = conta_legittimi + conta_crawler_benigni + conta_crawler_sospetti + conta_crawler_illegittimi + conta_ip_cdn
        print(f"[INFO] → Totale IP analizzati: {totale_ip} (somma categorie: {somma})", file=out)
        genera_grafico_classificazione_globale(conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi)

        totale_righe_classificate = righe_legittime + righe_benigne + righe_sospette + righe_illegittime
        # if totale_righe_classificate > 0:
        #     print("\n=== Percentuali su base numero di richieste (righe) ===", file=out)
        #     print(f"→ Totale righe classificate per categoria: {totale_righe_classificate}", file=out)
        #     print(f"→ {round(righe_legittime / totale_righe_classificate * 100, 2)}% delle righe appartengono a connessioni legittime", file=out)
        #     print(f"→ {round(righe_benigne / totale_righe_classificate * 100, 2)}% delle righe appartengono a crawler benigni", file=out)
        #     print(f"→ {round(righe_sospette / totale_righe_classificate * 100, 2)}% delle righe appartengono a attività sospette", file=out)
        #     print(f"→ {round(righe_illegittime / totale_righe_classificate * 100, 2)}% delle righe appartengono a crawler illegittimi", file=out)

        if CONTA_RICHIESTI > 0:
            print("\n[INFO] === Statistiche ip richiesti AbuseIPDB ===", file=out)
            print(f"[INFO] → Numero ip controllati: {CONTA_RICHIESTI}", file=out)
            print(f"[INFO] → Numero ip ritenuti malevoli da Classificazione Euristica e da AbuseIPDB: {CONTA_MALEVOLO_AIPEURISTIC}", file=out)
            print(f"[INFO] → Numero ip ritenuti legittimi da Classificazione Euristica e da AbuseIPDB: {CONTA_LEGITTIMI_AIPEURISTIC}", file=out)
            print(f"[INFO] → Numero ip ritenuti malevoli da  AbuseIPDB: {CONTA_MALEVOLO_AIP}", file=out)
            print(f"[INFO] → Numero ip ritenuti malevoli da  Classificazione Euristica: {CONTA_MALEVOLO_RICHIESTO}", file=out)
            print(f"[INFO] → Numero ip ritenuti malevoli da  AbuseIPDB ma non da Classificazione Euristica: {CONTA_NON_MALEVOLO_DA_EURISTICA}", file=out)
            print(f"[INFO] → Numero ip ritenuti malevoli da  Classificazione Euristica ma non da AbuseIPDB: {CONTA_NON_MALEVOLO_DA_AIP}", file=out)
            genera_grafico_confronto_abuseipdb(CONTA_MALEVOLO_AIPEURISTIC, CONTA_NON_MALEVOLO_DA_EURISTICA, CONTA_NON_MALEVOLO_DA_AIP, CONTA_LEGITTIMI_AIPEURISTIC)
        else:
            print(f"[WARNING] Nessun dato disponibile per generare statistiche di confronto con AbuseIPDB.", file=out)
        print(f"[SUCCESS] Righe totali processate: {righe_parse_totali}", file=out)
        print(f"[SUCCESS] Righe parse con fallback o ignorate: {righe_parse_fallback} ({round(righe_parse_fallback / righe_parse_totali * 100, 2)}%)", file=out)
        if righe_parse_fallback > 0:
            print("[OUTPUT] Log degli errori: salvato in log_parse_errori.txt", file=out)
        print("[OUTPUT] Ip salvati in ./output/risltati_classificazione.json", file=out)

    else:
        print("Nessuna sessione valida da analizzare.", file=out)

#funzione dedicata alla classificazione euristica
def classificazione_euristica(ip, records, features, req_per_sec, delta):
    identificazione = classify_ip(records)
    is_crawler_noto = identificazione.startswith("Crawler identificato") or identificazione.startswith("IP noto")
    classificazione_finale = None
    legittimi = benigni = sospetti = illegittimi = 0
    score = calcola_crawler_score(features, req_per_sec, delta)[0]
    if is_crawler_noto:
        if (features["login_attempts"] >= LOGIN_SOGLIA_MALEVOLO or 
            (req_per_sec >= FREQ_SOGLIA_ILLEGITTIMO and delta.total_seconds() >= 10) or 
            features["post_count"] >= POST_SOGLIA_MALEVOLO or features["error_4xx_percent"] >= ERROR_4XX_SOGLIA_MALEVOLO or features["env_file_requested"] > 0) and score >= 4:
            classificazione_finale = "Crawler noto con comportamento malevolo"
            illegittimi += 1
        elif score >= 3 and (
            (req_per_sec > FREQ_SOGLIA_LEGITTIMO or POST_SOGLIA_SOSPETTO <= features["post_count"] < POST_SOGLIA_MALEVOLO) or
            LOGIN_SOGLIA_SOSPETTO <= features["login_attempts"] < LOGIN_SOGLIA_MALEVOLO or 
            features["error_4xx_percent"] >= ERROR_4XX_SOGLIA_SOSPETTO or features["env_file_requested"] > 0):
            classificazione_finale = "Attività sospetta"
            sospetti += 1
        else:
            classificazione_finale = "Crawler noto (comportamento benigno)"
            benigni += 1

    elif score >= 3 and \
        req_per_sec >= FREQ_SOGLIA_ILLEGITTIMO and \
        features["post_count"] >= POST_SOGLIA_MALEVOLO and \
        features["login_attempts"] >= LOGIN_SOGLIA_MALEVOLO:
        classificazione_finale = "AI bot o bot molto aggressivo"
        illegittimi += 1

    elif (features["login_attempts"] >= LOGIN_SOGLIA_MALEVOLO or 
          (req_per_sec >= FREQ_SOGLIA_ILLEGITTIMO and delta.total_seconds() >= 10) or 
          features["post_count"] >= POST_SOGLIA_MALEVOLO or features["error_4xx_percent"] >= ERROR_4XX_SOGLIA_MALEVOLO or features["env_file_requested"] > 0) and score >= 3:
        classificazione_finale = "Crawler non identificato ma con attivita' malevola"
        illegittimi += 1

    elif score >= 3 and(
        LOGIN_SOGLIA_SOSPETTO <= features["login_attempts"] < LOGIN_SOGLIA_MALEVOLO or
        POST_SOGLIA_SOSPETTO <= features["post_count"] < POST_SOGLIA_MALEVOLO or 
        req_per_sec > FREQ_SOGLIA_LEGITTIMO or features["error_4xx_percent"] >= ERROR_4XX_SOGLIA_SOSPETTO or features["env_file_requested"] > 0):
        classificazione_finale = "Attivita' sospetta (bot o utente umano)"
        sospetti += 1

    elif score >= 1:
        classificazione_finale = "Altri bot (probabilmente benigni)"
        benigni += 1

    else:
        classificazione_finale = "Utente legittimo"
        legittimi += 1

    return classificazione_finale, legittimi, benigni, sospetti, illegittimi

    #funzione per il controllo randomizzato del confronto con AbuseIPDB
def controllo_random_abuseipdb(ip, classificazione_finale,CONTA_RICHIESTI,CONTA_MALEVOLO_AIP,CONTA_MALEVOLO_AIPEURISTIC,CONTA_NON_MALEVOLO_DA_EURISTICA,CONTA_LEGITTIMI_AIPEURISTIC,CONTA_MALEVOLO_RICHIESTO,CONTA_NON_MALEVOLO_DA_AIP):
    abuse_result = controlla_ip_abuseipdb(ip)
    if "error" in abuse_result:
        print(f"  → Classificazione AbuseIPDB: Errore ({abuse_result['error']})")
    else:
        print(f"  → [AbuseIPDB] Abuse Score: {abuse_result['abuse_score']}, Whitelisted: {abuse_result['is_whitelisted']}")
        CONTA_RICHIESTI += 1
        if abuse_result['abuse_score'] >= 90:
            CONTA_MALEVOLO_AIP += 1
            if ("crawler non identificato ma con attivita' malevola" in classificazione_finale.lower() or
                "crawler noto con comportamento malevolo" in classificazione_finale.lower() or 
                "AI bot o bot molto aggressivo" in classificazione_finale.lower()):
                CONTA_MALEVOLO_AIPEURISTIC += 1
            else:
                CONTA_NON_MALEVOLO_DA_EURISTICA += 1
        else:
            if ("crawler non identificato ma con attivita' malevola" not in classificazione_finale.lower() and
                "crawler noto con comportamento malevolo" not in classificazione_finale.lower() or 
                "AI bot o bot molto aggressivo" not in classificazione_finale.lower()):
                CONTA_LEGITTIMI_AIPEURISTIC += 1
        if ("crawler non identificato ma con attivita' malevola" in classificazione_finale.lower() or
            "crawler noto con comportamento malevolo" in classificazione_finale.lower() or 
            "AI bot o bot molto aggressivo" in classificazione_finale.lower()):
            CONTA_MALEVOLO_RICHIESTO += 1
            if abuse_result['abuse_score'] < 90:
                CONTA_NON_MALEVOLO_DA_AIP += 1
    return (CONTA_RICHIESTI,CONTA_MALEVOLO_AIP,CONTA_MALEVOLO_AIPEURISTIC,CONTA_NON_MALEVOLO_DA_EURISTICA,CONTA_LEGITTIMI_AIPEURISTIC,CONTA_MALEVOLO_RICHIESTO,CONTA_NON_MALEVOLO_DA_AIP)



def carica_traffico_da_log(log_file_path, ultima_posizione):
    traffic_by_ip = defaultdict(list)
    righe_parse_fallback = 0
    righe_parse_totali = 0

    with open(log_file_path, "r", encoding="utf-8", errors="replace") as file:
        file.seek(ultima_posizione)
        nuove_righe = file.readlines()
        nuova_posizione = file.tell()

    with open("./output/log_parse_errori.txt", "a", encoding="utf-8") as log_errori:
        for line in nuove_righe:
            righe_parse_totali += 1
            data, fallback = parse_log_line(line.strip())

            if data:
                forwarded_ip = data.get("forwarded_for", "-")

                via_forwarded_for = forwarded_ip != "-" and forwarded_ip.lower() != "unknown"
                if via_forwarded_for:
                    ip = forwarded_ip.split(',')[0].strip()
                    ip_origineCDN = data["ip"]
                else:
                    ip = data["ip"]
                    ip_origineCDN = None

                data["ip"] = ip
                data["ip_origineCDN"] = ip_origineCDN
                data["via_forwarded_for"] = via_forwarded_for

                traffic_by_ip[ip].append(data)

                if fallback:
                    righe_parse_fallback += 1
                    log_errori.write(f"Riga {righe_parse_totali} (fallback): {line}")
            else:
                righe_parse_fallback += 1
                log_errori.write(f"Riga {righe_parse_totali} (scartata): {line}")

    return traffic_by_ip, righe_parse_totali, righe_parse_fallback, nuova_posizione

def contoConteggio(ip, nuova_classificazione, vecchia_classificazione, output_per_categoria,
                   conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,
                   righe_legittime, righe_benigne, righe_sospette, righe_illegittime,
                   num_righe_ip):
    
    # Rimuove dalla vecchia categoria (se esiste e diversa)
    if vecchia_classificazione and vecchia_classificazione != nuova_classificazione:
        if ip in output_per_categoria.get(vecchia_classificazione, []):
            output_per_categoria[vecchia_classificazione].remove(ip)
            if vecchia_classificazione.lower().startswith("utente legittimo"):
                conta_legittimi -= 1
                righe_legittime -= num_righe_ip
            elif "comportamento benigno" in vecchia_classificazione.lower() or "altri bot" in vecchia_classificazione.lower():
                conta_crawler_benigni -= 1
                righe_benigne -= num_righe_ip
            elif "sospett" in vecchia_classificazione.lower():
                conta_crawler_sospetti -= 1
                righe_sospette -= num_righe_ip
            elif "malevol" in vecchia_classificazione.lower() or "aggressivo" in vecchia_classificazione.lower():
                conta_crawler_illegittimi -= 1
                righe_illegittime -= num_righe_ip

    # Aggiunge alla nuova categoria (solo se non già presente)
    if ip not in output_per_categoria[nuova_classificazione]:
        output_per_categoria[nuova_classificazione].append(ip)
        if nuova_classificazione.lower().startswith("utente legittimo"):
            conta_legittimi += 1
            righe_legittime += num_righe_ip
        elif "comportamento benigno" in nuova_classificazione.lower() or "altri bot" in nuova_classificazione.lower():
            conta_crawler_benigni += 1
            righe_benigne += num_righe_ip
        elif "sospett" in nuova_classificazione.lower():
            conta_crawler_sospetti += 1
            righe_sospette += num_righe_ip
        elif "malevol" in nuova_classificazione.lower() or "aggressivo" in nuova_classificazione.lower():
            conta_crawler_illegittimi += 1
            righe_illegittime += num_righe_ip

    return (conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,
            righe_legittime, righe_benigne, righe_sospette, righe_illegittime)

#funzione che parla con bridge per inserire le limitazioni
def invia_limit(ip, classificazione):
    classificazione = classificazione.lower()

    if (
        "attività sospetta" in classificazione
        or "attivita' sospetta" in classificazione
    ):
        coda = "sospetto"
    elif (
        "crawler noto con comportamento malevolo" in classificazione
        or "ai bot" in classificazione
        or "bot molto aggressivo" in classificazione
        or "crawler non identificato ma con attivita" in classificazione
    ):
        coda = "malevolo"
    else:
        return  # Nessuna azione per classificazioni non gestite

    # Silenzioso (senza output visibile)
    comando_httpie = f'http --ignore-stdin --quiet POST http://151.11.53.67:8000/limit ip_class={ip} queue={coda}'
    os.system(comando_httpie)



#corpo principale del programma
def esegui_classificazione(finestra_scelta):
    ultima_posizione = 0
    output_per_categoria = defaultdict(list)
    storico_connessioni = defaultdict(list)
    ip_stampati = set()
    righe_classificate_per_ip = defaultdict(int)
    righe_classificate_per_ip = defaultdict(int)

    #contatori per statistiche globali
    totale_ip = 0
    conta_legittimi = 0
    conta_crawler_benigni = 0
    conta_crawler_sospetti = 0
    conta_crawler_illegittimi = 0
    conta_ip_cdn = 0
    righe_parse_totali_cumulative = 0
    righe_parse_fallback_cumulative = 0


    #contatori per confronto con AbuseIPDB
    CONTA_MALEVOLO_AIP = 0
    CONTA_MALEVOLO_AIPEURISTIC = 0
    CONTA_NON_MALEVOLO_DA_AIP = 0
    CONTA_MALEVOLO_RICHIESTO = 0
    CONTA_RICHIESTI = 0
    CONTA_NON_MALEVOLO_DA_EURISTICA = 0
    CONTA_LEGITTIMI_AIPEURISTIC = 0

    #contatori per statistiche divise per righe su file di log
    righe_legittime = 0
    righe_benigne = 0
    righe_sospette = 0
    righe_illegittime = 0
    ATTESA=3 #tempo di attesa fra un controllo e il successivo
    tentativi_vuoti = 0

    ip_esclusi = set()
    ultima_classificazione = {}  
    cdn_ip_origini_per_ip = defaultdict(dict)
    try:
        while True:
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(ultima_posizione)
                    nuove_righe = f.readlines()
                    nuova_posizione = f.tell()
            except FileNotFoundError:
                time.sleep(ATTESA)
                continue

            if nuova_posizione == ultima_posizione:
                if ultima_posizione == 0:
                    time.sleep(finestra_scelta)
                    continue
                else:
                    time.sleep(ATTESA)
                    try:
                        with open(log_file, "r", encoding="utf-8", errors="replace") as f_check:
                            try:
                                print("\n[INFO] Fine file, attesa di nuovi Log o nuovo file...", file=sys.__stdout__)
                                f_check.seek(0, io.SEEK_END)
                                nuova_posizione_riaperto = f_check.tell()
                                if nuova_posizione_riaperto < ultima_posizione or nuova_posizione_riaperto == 0:
                                    ultima_posizione = 0
                                    print("\n[DONE] File troncato", file=sys.__stdout__)
                            except Exception as e_seek:
                                print(f"\n[ERROR] Errore durante seek/tell: {type(e_seek).__name__} - {e_seek}", file=sys.__stdout__)
                    except Exception as e_file:
                        print(f"\n[ERROR] Errore durante apertura file: {type(e_file).__name__} - {e_file}", file=sys.__stdout__)
                        time.sleep(1)

                    tentativi_vuoti += 1
                    print(f"[DEBUG] Tentativo vuoto #{tentativi_vuoti}", file=sys.__stdout__)
                    if tentativi_vuoti >= 5:
                        print("\n[DONE] Nessun nuovo log trovato dopo 5 tentativi. Interruzione programma.", file=sys.__stdout__)
                        break  # oppure: sys.exit(0)
                    continue



            # Ci sono nuove righe: processa e aggiorna il puntatore
            tentativi_vuoti = 0 
            traffic_by_ip, righe_parse_totali, righe_parse_fallback, nuova_posizione = carica_traffico_da_log(log_file, ultima_posizione)
            ultima_posizione = nuova_posizione

            if righe_parse_totali > 30000:
                statitischeAggiuntive = 0
                print("\n[INFO] Numero righe troppo elevato per effettuare statistiche approfondite", file=sys.__stdout__)
            else:
                statitischeAggiuntive = 1
                print("\n[INFO] Numero righe corretto per statistiche approfondite", file=sys.__stdout__)

            righe_parse_totali_cumulative += righe_parse_totali
            righe_parse_fallback_cumulative += righe_parse_fallback

            for ip_key, records in traffic_by_ip.items():
                ip = records[0]["ip"]
                for r in records:
                    if r.get("via_forwarded_for"):
                        ip_origineCDN = r.get("ip_origineCDN")
                        if ip_origineCDN:
                            cdn = identify_cdn_ip(ip_origineCDN, CDN_RANGES)
                            if cdn:
                                if ip_origineCDN not in cdn_ip_origini_per_ip[ip]:
                                    cdn_ip_origini_per_ip[ip][ip_origineCDN] = cdn
                                    conta_ip_cdn += 1


                # controllo aggiuntivo: l’IP stesso è un nodo CDN?
                cdn_direct = identify_cdn_ip(ip, CDN_RANGES)
                if cdn_direct and ip not in cdn_ip_origini_per_ip[ip]:
                    cdn_ip_origini_per_ip[ip][ip] = cdn_direct
                    conta_ip_cdn += 1
                storico_connessioni[ip].extend(records)
                tutte_le_richieste = storico_connessioni[ip]

                if ip not in ip_stampati:
                    totale_ip += 1
                ip_stampati.add(ip)

                features = estrai_feature_per_ip(tutte_le_richieste)

                if features["clicks"] < 5:
                    print(f"\nIP: {ip} → sessione troppo breve → considerata legittima")
                    vecchia_classificazione = ultima_classificazione.get(ip)
                    classificazione_finale = "Utente legittimo"
                    print(f"login=!{features["login_attempts"]}")

                    righe_precedenti = righe_classificate_per_ip[ip]
                    num_righe_ip = len(tutte_le_richieste) - righe_precedenti
                    if num_righe_ip <= 0:
                        continue
                    righe_classificate_per_ip[ip] = len(tutte_le_richieste)

                    (
                        conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,
                        righe_legittime, righe_benigne, righe_sospette, righe_illegittime
                    ) = contoConteggio(
                        ip, classificazione_finale, vecchia_classificazione, output_per_categoria,
                        conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,
                        righe_legittime, righe_benigne, righe_sospette, righe_illegittime,
                        num_righe_ip
                    )
                    ultima_classificazione[ip] = classificazione_finale
                    continue


                print(f"\nIP: {ip}")
                if cdn_ip_origini_per_ip[ip]:
                    origini = ", ".join(
                        f"{ip_cdn} ({cdn_ip_origini_per_ip[ip][ip_cdn]})"
                        for ip_cdn in sorted(cdn_ip_origini_per_ip[ip])
                    )
                    print(f"  → IP origine CDN multipla: {origini}")
                print(f"  → Numero richieste: {len(tutte_le_richieste)}", end="")

                try:
                    times = [parse_apache_time(r["time"]) for r in tutte_le_richieste]
                    delta = max(times) - min(times)
                    print(f" in delta tempo: {format_timedelta(delta)}")
                    req_per_sec = len(tutte_le_richieste) / delta.total_seconds() if delta.total_seconds() > 0 else len(tutte_le_richieste)
                    print(f"  → Frequenza richieste: {req_per_sec:.2f} req/sec" if req_per_sec >= 0.01 else "  → Frequenza richieste: < 0.01 req/sec")
                except Exception:
                    print("[WARNING] (errore nel calcolo tempo)")
                    req_per_sec = 0
                    delta = datetime.now() - datetime.now()

                print(f"  → Identificazione: {classify_ip(tutte_le_richieste)}")

                for k, v in features.items():
                    print(f"  → {k.replace('_', ' ').capitalize()}: {v}")

                score, motivi = calcola_crawler_score(features, req_per_sec, delta)
                #if statitischeAggiuntive == 1:
                enrichment = enrich_ip(ip)
                nazione = enrichment['country']
                print(f"  → Country: {nazione}")
                if nazione in NAZIONI_BLOCCATE:
                    print("   ATTENZIONE: IP PROVENIENTE DA NAZIONE NON LEGITTIMA")
                print(f"  → ASN: {enrichment['asn']}")
                print(f"  → PTR: {enrichment['ptr']}")
                print("       → Probabile provider cloud" if is_hosting_provider(enrichment["asn"]) or is_hosting_provider(enrichment["ptr"]) else "       → Probabile rete domestica o aziendale tradizionale")
                    
                print(f"  → Crawler score: {score} ({', '.join(motivi)})")

                classificazione_finale, legittimi, benigni, sospetti, illegittimi = classificazione_euristica(ip, tutte_le_richieste, features, req_per_sec, delta)

                righe_precedenti = righe_classificate_per_ip[ip]
                num_righe_ip = len(tutte_le_richieste) - righe_precedenti
                righe_classificate_per_ip[ip] = len(tutte_le_richieste)                
                # if classificazione_finale.lower().startswith("utente legittimo"):
                #     righe_legittime += num_righe_ip
                # elif "comportamento benigno" in classificazione_finale.lower() or "altri bot" in classificazione_finale.lower():
                #     righe_benigne += num_righe_ip
                # elif "sospett" in classificazione_finale.lower():
                #     righe_sospette += num_righe_ip
                # elif "malevol" in classificazione_finale.lower() or "aggressivo" in classificazione_finale.lower():
                #     righe_illegittime += num_righe_ip

                # conta_legittimi += legittimi
                # conta_crawler_benigni += benigni
                # conta_crawler_sospetti += sospetti
                # conta_crawler_illegittimi += illegittimi
                print(f"  → Classificazione euristica: {classificazione_finale}")
                #invia_limit(ip, classificazione_finale)
                #if statitischeAggiuntive == 1:
                    #(CONTA_RICHIESTI, CONTA_MALEVOLO_AIP, CONTA_MALEVOLO_AIPEURISTIC, CONTA_NON_MALEVOLO_DA_EURISTICA,CONTA_LEGITTIMI_AIPEURISTIC, CONTA_MALEVOLO_RICHIESTO, CONTA_NON_MALEVOLO_DA_AIP) = controllo_random_abuseipdb(ip, classificazione_finale, CONTA_RICHIESTI, CONTA_MALEVOLO_AIP, CONTA_MALEVOLO_AIPEURISTIC,CONTA_NON_MALEVOLO_DA_EURISTICA, CONTA_LEGITTIMI_AIPEURISTIC, CONTA_MALEVOLO_RICHIESTO, CONTA_NON_MALEVOLO_DA_AIP)

                vecchia_classificazione = ultima_classificazione.get(ip)
                (conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,righe_legittime, righe_benigne, righe_sospette, righe_illegittime) = contoConteggio(ip, classificazione_finale, vecchia_classificazione, output_per_categoria,conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,righe_legittime, righe_benigne, righe_sospette, righe_illegittime,num_righe_ip)
                ultima_classificazione[ip] = classificazione_finale
            if statitischeAggiuntive ==1:
                time.sleep(finestra_scelta)

            stampa_statistiche_finali(totale_ip, conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,CONTA_RICHIESTI, CONTA_MALEVOLO_AIPEURISTIC, CONTA_LEGITTIMI_AIPEURISTIC, CONTA_MALEVOLO_AIP,CONTA_MALEVOLO_RICHIESTO, CONTA_NON_MALEVOLO_DA_EURISTICA, CONTA_NON_MALEVOLO_DA_AIP,righe_parse_totali_cumulative, righe_parse_fallback_cumulative, conta_ip_cdn,righe_legittime, righe_benigne, righe_sospette, righe_illegittime)

            with open("output/risultati_classificazione.json", "w", encoding="utf-8") as f:
                json.dump(output_per_categoria, f, indent=4)

    except KeyboardInterrupt:
        print("\n[DONE] Analisi continua interrotta manualmente.", file=sys.__stdout__)
        stampa_statistiche_finali(totale_ip, conta_legittimi, conta_crawler_benigni, conta_crawler_sospetti, conta_crawler_illegittimi,CONTA_RICHIESTI, CONTA_MALEVOLO_AIPEURISTIC, CONTA_LEGITTIMI_AIPEURISTIC, CONTA_MALEVOLO_AIP,CONTA_MALEVOLO_RICHIESTO, CONTA_NON_MALEVOLO_DA_EURISTICA, CONTA_NON_MALEVOLO_DA_AIP,righe_parse_totali_cumulative, righe_parse_fallback_cumulative, conta_ip_cdn,righe_legittime, righe_benigne, righe_sospette, righe_illegittime)
        with open("output/connessioni_totali_giornata.json", "w", encoding="utf-8") as f:
            json.dump(storico_connessioni, f, indent=4)

def stampa_banner_iniziale():
    banner = r"""
                +--------------------------------------------------------------------------------------------------------+
                |                                                                                                        |
                |         █████╗ ██████╗ ███████╗       ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗         |
                |        ██╔══██╗██╔══██╗██╔════╝      ██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗        |
                |        ███████║██████╔╝███████╗█████╗██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝        |
                |        ██╔══██║██╔══██╗╚════██║╚════╝██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗        |
                |        ██║  ██║██║  ██║███████║      ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║        |
                |        ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝        |
                |                            Analysis-and-recognition-of-suspicious-crawlers                             |
                +--------------------------------------------------------------------------------------------------------+
"""
    print(banner, file=sys.__stdout__)


def mostra_caricamento(messaggio="[LOADING]	Analisi in corso... premi Ctrl+C per interrompere"):
    def animazione():
        simboli = ["|", "/", "-", "\\"]
        i = 0
        while not stop_event.is_set():
            print(f"\r{messaggio} {simboli[i % len(simboli)]}", end="", file=sys.__stdout__)
            i += 1
            time.sleep(0.1)
        print("\r[DONE] Analisi completata.                                       ", file=sys.__stdout__)
    stop_event = threading.Event()
    thread = threading.Thread(target=animazione)
    thread.start()
    return stop_event


# Modalità scanner, analizza traffico per finestra temporale
def scanner_velocita_trafico(log_file_path, durata_ascolto=30, intervallo_scan=5):
    finestra_scelta = 0
    out = sys.__stdout__
    print("\n[info] Avviata modalità scanner per 30 secondi.", file=out)

    with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        ultima_posizione = f.tell()

    # Stima del tempo medio per arricchimento IP
    ip_test = "8.8.8.8"
    start_enrich = time.time()
    enrich_ip(ip_test)
    controlla_ip_abuseipdb(ip_test)
    enrich_duration = time.time() - start_enrich
    print(f"[SCANNER] Tempo medio per chiamare api: {enrich_duration:.4f} s", file=out)

    inizio = time.time()
    while time.time() - inizio < durata_ascolto:
        time.sleep(intervallo_scan)

        inizio_ciclo = time.time()
        with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(ultima_posizione)
            nuove_righe = f.readlines()
            nuova_posizione = f.tell()
        fine_ciclo = time.time()

        intervallo_reale = fine_ciclo - inizio_ciclo
        righe_nuove = len(nuove_righe)
        righe_al_sec = righe_nuove / intervallo_scan if intervallo_scan > 0 else 0

        tempo_totale_stimato = righe_nuove * enrich_duration

        if tempo_totale_stimato <= 60:
            finestra_scelta = 60
        elif tempo_totale_stimato <= 300:
            finestra_scelta = 300
        else:
            finestra_scelta = 600

        print(f"[SCANNER] Nuove righe: {righe_nuove}, Velocità: {righe_al_sec:.2f} righe/sec → "
              f"Finestra: {finestra_scelta//60} min (Stima tempo analisi: {tempo_totale_stimato:.1f}s)", file=out)

        ultima_posizione = nuova_posizione

    print(f"\n[SUCCESS] Scanner terminato. Finestra selezionata: {finestra_scelta//60} minuti\n", file=out)
    return finestra_scelta

def aggiorna_whitelist_da_github():
    url = "https://raw.githubusercontent.com/AnTheMaker/GoodBots/main/all.ips"
    destinazione = "./lists/whitelists.ips"

    try:
        print("[INFO] Scaricamento lista whitelist aggiornata da GitHub...", file=sys.__stdout__)
        urllib.request.urlretrieve(url, destinazione)
        print("[SUCCESS] Lista whitelist aggiornata in:", destinazione, file=sys.__stdout__)
    except Exception as e:
        print(f"[WARNING] Impossibile aggiornare la whitelist da GitHub: {e}", file=sys.__stdout__)


if __name__ == "__main__":
    stampa_banner_iniziale()
    out = sys.__stdout__

    print("\n[INPUT] Scegli la modalità di esecuzione:", file=out)
    print("\t1 - Modalità scanner (valutazione e poi analisi)", file=out)
    print("\t2 - Modalità file (analisi di un file completo)", file=out)
    scelta = input("Inserisci 1 o 2: ").strip()

    try:
        if scelta == "1":
            print("\t[INFO] Modalità selezionata: 1 (Modalità scanner)\n", file=out)
            finestra = scanner_velocita_trafico(log_file)
            stop_event = mostra_caricamento()
            esegui_classificazione(finestra)
        elif scelta == "2":
            print(f"\t[INFO] Modalità selezionata: 2 (Analisi del file {log_file})\n", file=out)
            #aggiorna_whitelist_da_github()
            stop_event = mostra_caricamento()
            esegui_classificazione(FINESTRA_DEFAULT)
        else:
            print("[ERROR] Scelta non valida. Uscita.")
    except FileNotFoundError:
        print(f"[ERROR] Errore: il file '{log_file}' non è stato trovato.")
    except Exception as e:
        print(f"[ERROR] Errore durante l'elaborazione: {e}")
    finally:
        stop_event.set()
        reader_country.close()
        reader_asn.close()