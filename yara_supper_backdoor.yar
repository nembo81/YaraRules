rule backdoor_supper_mem {
     meta:
        author = "Simone Marinari"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        os = "windows"
       strings:
                $b1 = "rundll32.exe %s,run %s" fullword
        	$a2 = "remove"
		$a3 = "test"
		$a4 = "socks.dll"
		$a5 = "main.dll"
		$a6 = /%s\/tmpf\d+\.dll/
		$a7 = "%s/s01bafg" fullword wide
		$a8 = "%d.%d.%d.%d" fullword wide
		$a9 = "%s/tmp%d.dll" fullword
                $a10 = "%s/ribdgfj"
     condition:
        $b1 and 7 of($a*)
}
