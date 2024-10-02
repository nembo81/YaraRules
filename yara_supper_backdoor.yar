rule backdoor_supper_mem {
     meta:
        author = "Simone Marinari"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        os = "windows"
       strings:
        $b1 = "rundll32.exe %s,run %s" fullword wide
		$a2 = "remove"
		$a3 = "test"
		$a4 = "socks.dll"
		$a5 = "main.dll"
     condition:
        $b1 AND 3 of ($a*)
     }