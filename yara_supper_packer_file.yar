import "pe"
rule SupperPacker : FILE {
    meta:
        name        = "Supper Team Packer detected on Supper backdoor,keylogger and interlock ransomware pe"
        author      = "Simone Marinari"
	ref         = "https://x.com/nembo81pr/status/1841390890167775551"
        created     = "2024-10-22"
        tlp         = "TLP:white"
        sample      = "64a0ab00d90682b1807c5d7da1a4ae67cde4c5757fc7d995d8f126f0ec8ae983"

    strings:
		$a1 = { C7 45 E0 56 69 72 74 C7 45 E4 75 61 6C 50 C7 45 E8 72 6F 74 65 C7 45 EC 63 74 00 00 } 
		$a2 = { C7 45 E0 6B 65 72 6E C7 45 E4 65 6C 33 32 C7 45 E8 2E 64 6C 6C C6 45 EC 00 00 }

	condition:
	    uint16(0)==0x5a4d and filesize <1500KB and any of ($a*)
}
