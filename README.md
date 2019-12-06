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
The system will reboot after the setup.

## Telegram setup (as root) 
You may edit the `/home/auth/telegram.apikey` and `/home/auth/telegram.chatid` to
get telegram notifications.
