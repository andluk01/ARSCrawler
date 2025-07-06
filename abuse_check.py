import requests

api_key = 'e9584446d64bb2b71a0e1ae78115037d0ef627c7022ceaa38e7736c13c5165daf823a91ab81c579b'

def controlla_ip_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }

        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", "N/A")
            is_whitelisted = data.get("isWhitelisted", False)
            return {
                "abuse_score": abuse_score,
                "is_whitelisted": is_whitelisted
            }
        else:
            return {
                "error": f"Errore risposta API: {response.status_code}"
            }
    except Exception as e:
        return {
            "error": f"Eccezione nella richiesta: {e}"
        }
