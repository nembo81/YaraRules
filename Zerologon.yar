rule Zerologon_unpatched
{
        meta:
                ref = "https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc"
		description = "Detection of unpatched-exploitable netlogon.dll in LSASS memory.Use it on LSASS dump file from volatility memdump or from Sysinternals procdump"
		author = "Simone Marinari"
		date = "03/10/2020"
		reference = "mettere github"
				
    strings:

        $NETLOGON = "NetLogon.DLL" wide
        $STRING1 = "VulnerableChannelAllowList" wide
        
    condition:
        $NETLOGON and not $STRING1
}

rule Zerologon_Scanned_Exploited
{
        meta:
                ref = "CVE-2020-1472"
        description = "Detection of Zerologon Scanner/Exploit using null client credentials (it finds scanning attempts on patched systems too)"
        author = "Cynet"
        date = "24/09/2020"
        reference = "https://www.cynet.com/zerologon"
        reference_1 = "https://www.secura.com/blog/zero-logon"
                
    strings:
        $CVE20201472 = { 00 24 00 00 00 06 00 ?? 00 00 00 00 00 00 00 ?? 00 00 00 [2-510] 00 00 00 00 00 00 00 00 ff ff 2f 21 }


    condition:
        $CVE20201472
}