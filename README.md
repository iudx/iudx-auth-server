# IUDX Authentication, Authorization, and Accounting (AAA) Server 

## Installation on OpenBSD (as root) 
```
ftp -o - https://iudx.org.in/install/auth | sh
```
This will install the AAA server at `/home/iudx-auth-server/`.

The system will reboot after the setup. After which, the AAA server should be
ready at https://localhost.

Please read the API documentation at http://auth.iudx.org.in

## Telegram setup (as root) 
You may edit the files:

`/home/iudx-auth-server/telegram.apikey`
	and
`/home/iudx-auth-server/telegram.chatid`

to get telegram notifications.

## Project organization 
```
.
|-- CCAIndia2014.cer		// CCA's 2014 certificate
|-- CCAIndia2015.cer		// CCA's 2015 certificate
|-- LICENSE			// ISC License
|-- README.md			// Readme file
|-- ca.iudx.org.in.crt		// ca.iudx.org.in's certificate
|-- check.sh			// JavaScript linter
|-- crl.js			// stores the certificate revocation list in DB
|-- db-cleanup.sql		// cleans non-introspected tokens
|-- formal-proof		// WIP formal proof of AAA server code
|   |-- header
|   |-- input
|   |-- run.sh
|   `-- to-prove
|-- https.js			// the main AAA server code
|-- install			// the install script for the AAA server	
|-- pf.conf			// the firewall rules
|-- postgresql.sql		// the database schema
|-- public			// the documentation for each API
|   `-- help
|       |-- acl
|       |   |-- append.txt
|       |   `-- set.txt
|       |-- acl.txt
|       |-- audit
|       |   `-- tokens.txt
|       |-- certificate-info.txt
|       |-- copy.sh
|       |-- group
|       |   |-- add.txt
|       |   |-- delete.txt
|       |   `-- list.txt
|       |-- token
|       |   |-- introspect.txt
|       |   |-- revoke-all.txt
|       |   `-- revoke.txt
|       `-- token.txt
|-- rc.local			// the code to be run at every startup
|-- run				// the nodejs https.js shell script
|-- run.crl			// the nodejs crl.js shell script 
|-- run.crl.tmux		// run the 'run.crl' file in tmux
|-- run.tmux			// run the 'run' file in tmux
|-- setup			// sets up the AAA server
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
|-- www				// website of auth.iudx.org.in
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
