cat partials/head.sh > main.sh
cat partials/curl_body.sh >> main.sh
cat partials/tail.sh >> main.sh
chmod a+x main.sh
./main.sh $1 $2 $3
rm main.sh
