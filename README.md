# India Urban Data eXchange (IUDX) Authentication, Authorization, and Accounting (AAA) Server

IUDX AAA is the Auth server for accessing [IUDX](https://www.iudx.org.in) services.

## 1. Read the API documentation
Please visit [IUDX Auth server](http://auth.iudx.org.in) for APIs and flows.

## 2. Installation
### 2.1 Install OpenBSD (prerequisite)
Please see [OpenBSD FAQ - Installation Guide](https://www.openbsd.org/faq/faq4.html). e.g. [INSTALLATION NOTES for OpenBSD/amd64 6.6
](https://ftp.openbsd.org/pub/OpenBSD/6.6/amd64/INSTALL.amd64)

### 2.2 Installation of IUDX Auth server (as root) 

After installing OpenBSD, please run the command as root:

```
ftp -o - https://iudx.org.in/install/auth | sh
```

This will install the Auth server at `/home/iudx-auth-server/`.

The system will reboot after the setup; after which, the Auth server should be
ready at https://localhost.

Please read the API documentation at http://auth.iudx.org.in

### 2.3 Setup telegram (as root) 
You may edit the files:

`/home/iudx-auth-server/telegram.apikey`
	and
`/home/iudx-auth-server/telegram.chatid`

to get telegram notifications.

## 3. After install (as root) 
You may run the command

```
tmux ls
```

to find the tmux sessions to manage. 

Also, change the `/home/iudx-auth-server/https-certificate.pem` and `/home/iudx-auth-server/https-key.pem` with real TLS certificate and key.

## 4. LICENSE

This project is released under [ISC license](https://opensource.org/licenses/ISC); and the [node-aperture](https://github.com/rbccps-iisc/node-aperture) is released under [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

## 5. Database structure

Below is the list of tables used. There are no join queries in the project.

![Alt text](https://raw.githubusercontent.com/iudx/iudx-auth-server/master/er.svg?sanitize=true)

## 6. Project organization 
```
.
|-- CCAIndia2014.cer		// CCA's 2014 certificate
|-- CCAIndia2015.cer		// CCA's 2015 certificate
|-- LICENSE			// ISC License
|-- README.md			// Readme file
|-- er.plantuml			// The database structure in plantuml 
|-- er.svg			// The database structure in svg format 
|-- ca.iudx.org.in.crt		// ca.iudx.org.in's certificate
|-- check.sh			// JavaScript linter
|-- crl.js			// stores the certificate revocation list in DB
|-- db-cleanup.sql		// cleans non-introspected tokens
|-- formal-proof		// WIP formal proof of Auth server code
|   |-- header
|   |-- input
|   |-- run.sh
|   `-- to-prove
|-- https.js			// the main Auth server code
|-- install			// the install script for the Auth server	
|-- pf.conf			// the firewall rules to be copied to /etc
|-- schema.sql			// the database schema
|-- rc.local			// the code to be run at every startup (dest = /etc)
|-- run				// the nodejs https.js shell script
|-- run.crl			// the nodejs crl.js shell script 
|-- run.crl.tmux		// run the 'run.crl' file in tmux
|-- run.tmux			// run the 'run' file in tmux
|-- setup			// sets up the Auth server
|-- setup.postgresql.openbsd	// sets up the postgresql server
|-- test			// test cases
|   |-- auth.py			// SDK file from pyIUDX
|   |-- check			// linter for test cases	
|   |-- consumer.pem		// certificate of the data consumer
|   |-- f-server.pem		// certificate of the fake server
|   |-- init.py			// initialization of testing code 
|   |-- provider.pem		// certificate of the data provider
|   |-- r-server.pem		// certificate of a valid resource server
|   |-- run			// runs the test
|   |-- test-groups.py		// test cases for group based access control
|   `-- test-tokens.py		// general test cases
|-- download-website.sh		// clones the auth.iudx.org.in website
|-- auth.iudx.org.in		// website of auth.iudx.org.in
|   |-- acl-append.txt
|   |-- acl-set.txt
|   |-- acl.txt
|   |-- audit-tokens.txt
|   |-- ca-list.txt
|   |-- certificate-info.txt
|   |-- consumer.svg
|   |-- group-add.txt
|   |-- group-delete.txt
|   |-- group-list.txt
|   |-- iudx.png
|   |-- setup.svg
|   |-- token-introspect.txt
|   |-- token-revoke-all.txt
|   |-- token-revoke.txt
|   `-- token.txt
`---'
```
