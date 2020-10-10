rule Bluekeep_exploit_scanner
{
    meta:
        ref = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708"
        description = "In memory detection of Bluekeep scanner or exploit.Use it with yara standalone executable on memory dump files"
	    author = "Simone Marinari"
	    date = "10/10/2020"
	    reference = "https://github.com/nembo81/YaraRules/blob/main/Bluekeep.yar"
				
    strings:

        $CHANNEL_T120 = { 4d 53 5f 54 31 32 30 }
        $CHANNEL_XXX = { 4d 53 5f 58 58 58 }
        
    condition:
        all of them
}