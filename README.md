# IUDX Authentication, Authorization, and Accounting (AAA) Server 

## Installation on OpenBSD (as root) 
```
ftp -o - https://iudx.org.in/install/auth | sh
```
This will install the AAA server at `/home/auth/`.

The system will reboot after the setup. After which, the AAA server should be
ready at https://localhost.

Please read the API documentation at http://auth.iudx.org.in

## Telegram setup (as root) 
You may edit the files:

`/home/auth/iudx-auth-server/telegram.apikey`
	and
`/home/auth/iudx-auth-server/telegram.chatid`

to get telegram notifications.
