ftp -o - https://raw.githubusercontent.com/iudx/iudx-auth-server/master/crl.js > crl.js

if [ $1 != 0 ]
then
	echo "Failed to deploy crl.js!"
	exit
fi

ftp -o - https://raw.githubusercontent.com/iudx/iudx-auth-server/master/https.js > https.js

if [ $1 != 0 ]
then
	echo "Failed to deploy https.js!"
	exit
fi

echo "Success"
tmux kill-session -t node
./run.tmux
