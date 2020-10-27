rule Zerologon_patched
{
    meta:
        ref = "https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc"
        description = "Detection of patched netlogon.dll in LSASS memory.Use it with volatility yarascan plugin or with yara standalone executable on memory dump files"
	author = "Simone Marinari"
	date = "03/10/2020"
	reference = "https://github.com/nembo81/YaraRules"
				
    strings:

        $NEWFUNCTION = "VulnerableChannelAllowList" wide
        
    condition:
        $NEWFUNCTION
}

rule Zerologon_DCSYNC_Scanned_Exploited
{
    meta:
        ref = "CVE-2020-1472"
        description = "Detection of Zerologon DCYSNC exploit without null password reset"
        author = "Simone Marinari"
        date = "08/10/2020"
        reference = "https://github.com/nembo81/YaraRules"
	reference_1 = "https://dirkjanm.io/a-different-way-of-abusing-zerologon/"
                
    strings:
        $CVE20201472_DCSYNC = { 00 24 00 00 00 06 00 [1-3] 00 00 00 00 00 00 00 ?? 00 00 00 [2-510] 00 00 00 00 00 00 00 00 ?? ?? ef ff 2e 21 }

    condition:
        $CVE20201472_DCSYNC
}

rule Zerologon_Scanned_Exploited
{
    meta:
         ref = "CVE-2020-1472"
         description = "Detection of Zerologon Scanner/Exploit (it finds scanning attempts on patched systems too)"
         author = "Simone Marinari"
         date = "27/10/2020"
         reference_original_rule = "https://www.cynet.com/zerologon"
         reference_1 = "https://www.secura.com/blog/zero-logon"
                
    strings:
        
        $poc_exploit = { 00 24 00 00 00 06 00 ?? 00 00 00 00 00 00 00 ?? 00 00 00 [2-510] 00 00 00 00 00 00 00 00 ff ff 2f 21 }
        $sharpzerologon_auth = { 00 24 00 00 00 00 00 06 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 [2-510] 00 00 00 00 00 00 00 00 ff ff 2f 21 }

    condition:
        $sharpzerologon_auth or $poc_exploit
}
