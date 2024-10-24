rule backdoor_supper_mem {
     meta:
        author = "Simone Marinari"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        os = "windows"
       strings:
        $b1 = "rundll32.exe %s,run %s" fullword
		$a1 = "socks.dll"
		$a2 = "main.dll"
		$a3 = /%s\/tmpf\d+(\.dll|\.exe)/
		$a4 = "%s/s01bafg" fullword wide
		$a5 = "%d.%d.%d.%d" fullword wide
		$a6 = "%s/tmp%d.dll" fullword
        $a7 = "%s/ribdgfj"
		$a8 = "schtasks.exe /Create" fullword
     condition:
        $b1 or 3 of($a*)
}
