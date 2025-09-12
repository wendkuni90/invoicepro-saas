import requests
from django.conf import settings

def verify_captcha(token: str, remote_ip: str = None) -> bool:
    """
    Vérifie le token reCAPTCHA v3 avec Google.
    """
    secret_key = settings.RECAPTCHA_SECRET_KEY
    if settings.DEBUG:
        # ⚠️ En dev, on bypass pour les tests
        return True

    if not secret_key:
        return False
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {
        "secret": secret_key,
        "response": token,
    }
    if remote_ip:
        data["remoteip"] = remote_ip

    try:
        response = requests.post(url, data=data)
        result = response.json()
        return result.get("success", False)
    except Exception:
        return False
