# YaraRules
Yara rules repository

- Zerologon.yar (tested on Windows 2012R2,2016 and 2019). It can be used with yarascan volatility plugin or with yara standalone executable on memory dump files
  - Detect if a scanner/exploit (with null password reset) has been executed since the last startup and it prints out "Zerologon_Scanned_Exploited" on these cases :
      - Patched server : a scanner/exploit has been executed without consequences
      - Vulnerable server : a scanner/exploit has been executed (check NTDS.DIT - Windows Events for more detections)
  - Detect if a scanner/exploit (with DCSYNC - without null password reset ) has been executed since the last startup and it prints out "Zerologon_DCSYNC_scanned_exploited" on these cases :
      - Patched server : a scanner/exploit has been executed without consequences
      - Vulnerable server : a scanner/exploit has been executed (check Windows Event 4624 on both abused DC for more detections) 
  - Patch check :
      - Prints out "Zerologon_patched" if the server is updated
      - No output if the server is vulnerable to zerologon.
      
    
- Bluekeep.yar (tested on Windows 2008R2).Use it with yara standalone executable on memory dump files
  - Detect if a scanner/exploit has been executed since the last startup and it prints out "Bluekeep_exploit_scanner"
