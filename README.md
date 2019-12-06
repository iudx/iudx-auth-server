# IUDX Auth Server 

## On OpenBSD (as root)
```
pkg_add git 
``` 

## Installation (as root) 
```
mkdir /home/auth
cd /home/auth
git clone https://github.com/iudx-auth-server
cd iudx-auth-server
./setup
```
The system will reboot after the setup. After reboot, the auth server should be
ready at port 443.

Please read the documentation at http://auth.iudx.org.in

## Telegram setup (as root) 
You may edit the `/home/auth/telegram.apikey` and `/home/auth/telegram.chatid` to
get telegram notifications.
