import requests

def check_urlhaus(url: str):
    """URLhaus (Abuse.ch) API - No API Key Required"""
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {'url': url}
    try:
        response = requests.post(endpoint, data=data, timeout=5)
        if response.status_code == 200:
            json_res = response.json()
            # Agar query success hai aur URL active malware hai
            if json_res.get('query_status') == 'ok' and json_res.get('url_status') == 'online':
                return True, 100 # 100% Malicious
        return False, 0
    except Exception:
        return False, 0