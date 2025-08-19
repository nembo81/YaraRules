rule backdoor_pipemagic {
     meta:
        author = "Simone Marinari"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        os = "windows"
       strings:
        $b1 = "44.203.203.133"
        $b2 = "cloudapp.azure"
		$a1 = "\\\\.\\pipe\\magic"
		$a2 = "\\\\.\\pipe\\1.%s"
		$a3 = "127.0.0.1:8082"
     condition:
        ($b1 or $b2) or 2 of($a*)
}
