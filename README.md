# IUDX Auth Server 

## Installation on OpenBSD (as root) 
```
ftp -o - https://iudx.org.in/install/auth | sh
```
This will install the Auth server at `/home/auth/`.

The system will reboot after the setup. After which, the auth server should be
ready at https://localhost.

Please read the API documentation at http://auth.iudx.org.in

## Telegram setup (as root) 
You may edit the `/home/auth/telegram.apikey` and `/home/auth/telegram.chatid` to
get telegram notifications.
