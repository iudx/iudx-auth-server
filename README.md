# India Urban Data eXchange (IUDX) Authentication, Authorization, and Accounting (AAA) Server
![ISC license](https://img.shields.io/badge/license-ISC-blue.svg) [![builds.sr.ht status](https://builds.sr.ht/~iudx-auth.svg)](https://builds.sr.ht/~iudx-auth?) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/6e6d74bd17a146c1a8288c4d98ca3e26)](https://www.codacy.com/gh/iudx/iudx-auth-server?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=iudx/iudx-auth-server&amp;utm_campaign=Badge_Grade) [![CodeFactor](https://www.codefactor.io/repository/github/iudx/iudx-auth-server/badge)](https://www.codefactor.io/repository/github/iudx/iudx-auth-server) [![Known Vulnerabilities](https://snyk.io/test/github/iudx/iudx-auth-server/badge.svg?targetFile=package.json)](https://snyk.io/test/github/iudx/iudx-auth-server?targetFile=package.json)

[![dependencies Status](https://david-dm.org/iudx/iudx-auth-server/status.svg)](https://david-dm.org/iudx/iudx-auth-server) [![devDependencies Status](https://david-dm.org/iudx/iudx-auth-server/dev-status.svg)](https://david-dm.org/iudx/iudx-auth-server?type=dev)

IUDX-AAA is the Authentication, Authorization, and Accounting server for accessing [IUDX](https://www.iudx.org.in) services.

## 1. Read the API documentation
Please visit [IUDX Auth server](http://auth.iudx.org.in) for APIs and flows.

## 2. Installation
### 2.1 Install OpenBSD 6.7 (prerequisite)
Please see [OpenBSD FAQ - Installation Guide](https://www.openbsd.org/faq/faq4.html). e.g. [INSTALLATION NOTES for OpenBSD/amd64 6.7](https://ftp.openbsd.org/pub/OpenBSD/6.7/amd64/INSTALL.amd64)

### 2.2 Installation of IUDX Auth server (as root) 

After installing OpenBSD, please run the command as root:

```bash
ftp -o - https://iudx.org.in/install/auth | sh
```

This will install the Auth server at `/home/iudx-auth-server/`.

The system will reboot after the setup; after which, the Auth server should be
ready at <https://localhost>.

### 2.3 Setup telegram (as root) 
You may edit the files:

`/home/iudx-auth-server/telegram.apikey`
	and
`/home/iudx-auth-server/telegram.chatid`

to get telegram notifications.

## 3. After install (as root) 
You may run the command

```bash
tmux ls
```

to find the tmux sessions to manage. 

Also, change the `/home/iudx-auth-server/https-certificate.pem` and `/home/iudx-auth-server/https-key.pem` with real TLS certificate and key.

## 4. Setup backups on tarsnap (as root)
```bash
cd /home/iudx-auth-server
./setup-backup.sh
```

This will store backups on /root/backups

## 5. LICENSE

This project is released under [ISC license](https://opensource.org/licenses/ISC); and the [node-aperture](https://github.com/rbccps-iisc/node-aperture) is released under [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

## 6. Database structure

Below is the list of tables used. There are no join queries in the project.

![Alt text](https://raw.githubusercontent.com/iudx/iudx-auth-server/master/er.svg?sanitize=true)

## 7. Project organization 
```bash
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
|-- main.js			// the main Auth server code
|-- install			// the install script for the Auth server	
|-- pf.conf			// the firewall rules to be copied to /etc
|-- schema.sql			// the database schema
|-- rc.local			// the code to be run at every startup (dest = /etc)
|-- run				// the nodejs main.js shell script
|-- run.crl			// the nodejs crl.js shell script 
|-- run.crl.tmux		// run the 'run.crl' file in tmux
|-- run.tmux			// run the 'run' file in tmux
|-- setup			// sets up the Auth server
|-- setup.postgresql.openbsd	// sets up the postgresql server
|-- test			// test cases
|   |-- auth.py			// SDK file from pyIUDX
|   |-- check			// linter for test cases	
|   |-- init.py			// initialization of testing code 
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
