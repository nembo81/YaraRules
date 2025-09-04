rule backdoor_AdaptixC2_http_beacon {
     meta:
        author = "Simone Marinari"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        os = "windows"
       strings:
        $b1 = "AdaptixC2"
        $b2 = "X-Beacon-Id"
        $b3 = "X-Session-Id"
		$a1 = "Mozilla/5.0"
		$a2 = "POST /"
     condition:
        $b1 or (($b2 or $b3) and 1 of($a*))
}
