rule Suspicious_PowerShell_Indicators
{
    meta:
        description = "Educational detection of obvious PowerShell execution/download indicators"
        severity = "medium"
        category = "execution"
    strings:
        $a = "powershell" nocase
        $b = "downloadstring" nocase
        $c = "invoke-expression" nocase
        $d = "frombase64string" nocase
    condition:
        1 of them
}

rule Suspicious_Windows_Lolbin_Indicators
{
    meta:
        description = "Educational detection of common Windows utility indicators"
        severity = "medium"
        category = "execution"
    strings:
        $a = "rundll32.exe" nocase
        $b = "regsvr32.exe" nocase
        $c = "mshta.exe" nocase
        $d = "certutil.exe" nocase
        $e = "bitsadmin.exe" nocase
    condition:
        1 of them
}

rule Suspicious_Persistence_Indicators
{
    meta:
        description = "Educational detection of common persistence-related strings"
        severity = "medium"
        category = "persistence"
    strings:
        $a = "schtasks" nocase
        $b = "CurrentVersion\\Run" nocase
        $c = "startup" nocase
        $d = "serviceName" nocase
    condition:
        1 of them
}

rule Suspicious_Credential_Access_Indicators
{
    meta:
        description = "Educational detection of credential-access terminology"
        severity = "high"
        category = "credential-access"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "credential" nocase
        $d = "lsass" nocase
    condition:
        1 of them
}

rule Suspicious_Encoded_Content_Indicators
{
    meta:
        description = "Educational detection of common encoded-content markers"
        severity = "medium"
        category = "obfuscation"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "base64" nocase
        $c = "FromBase64String" nocase
    condition:
        1 of them
}

rule Suspicious_Network_Indicators
{
    meta:
        description = "Educational detection of network-related strings"
        severity = "low"
        category = "network"
    strings:
        $a = "http://" nocase
        $b = "https://" nocase
        $c = "WinHttp" nocase
        $d = "InternetOpen" nocase
    condition:
        2 of them
}
