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

## Brute force dns

```
dnsrecon
```

## Subdomain discovery

```
https://github.com/aboul3la/Sublist3r
```

## virtual hosts

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP
```