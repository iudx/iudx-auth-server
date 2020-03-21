#!/bin/sh

CRL_JS="https://raw.githubusercontent.com/iudx/iudx-auth-server/master/crl.js"
HTTPS_JS="https://raw.githubusercontent.com/iudx/iudx-auth-server/master/https.js"

if ! ftp -o - $CRL_JS > crl.js
then
	echo "Failed to deploy crl.js!"
	exit
fi

if ! ftp -o - $HTTPS_JS > https.js
then
	echo "Failed to deploy https.js!"
	exit
fi

echo "Success"
tmux kill-session -t node
./run.tmux
