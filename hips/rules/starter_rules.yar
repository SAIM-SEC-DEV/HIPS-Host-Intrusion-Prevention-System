rule Suspicious_Process_Injection_Strings
{
    meta:
        description = "Detects common suspicious strings related to process injection and hooking"
        author = "HIPS Malware Module"
        severity = "CRITICAL"

    strings:
        $s1 = "CreateRemoteThread"
        $s2 = "VirtualAllocEx"
        $s3 = "SetWindowsHookEx"
        $s4 = "WriteProcessMemory"
        $s5 = "OpenProcess"

    condition:
        any of them
}

rule Suspicious_PowerShell_Strings
{
    meta:
        description = "Detects suspicious PowerShell execution strings"
    
    strings:
        $p1 = "-ExecutionPolicy Bypass"
        $p2 = "-WindowStyle Hidden"
        $p3 = "EncodedCommand"
        $p4 = "IEX (New-Object Net.WebClient)"

    condition:
        any of them
}
