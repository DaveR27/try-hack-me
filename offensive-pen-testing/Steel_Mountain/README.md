# Steel Mountain

## Introduction

You find the employee of the month by going to the ip from your browser and inspecting the html. The name is on the png.

## Inital Access

Get CVE from googling file server

Use metasploit to connect

cd to desktop and get flag

## Privilege escalation

```
To enumerate this machine, we will use a powershell script called PowerUp, that's purpose is to evaluate a Windows machine and determine any abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."
```

upload PowerUp.ps1

```
upload try-hack-me/offensive-pen-testing/Steel_Mountain/PowerUp.ps1
```

```
load powershell
powershell_shell
. .\PowerUp.ps1
Invoke-AllChecks
```

The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able

## without metasploit

Use the listed exploit to get windows nc onto the machine and get a reverse shell

use winPeas to find what is vuln

mv advance.exe to the vuln Advanced SystemCare dir

run advance to get root shell

