cat header > input

cat ../https.js | grep prover9: | cut -f2- -d':' >> input

echo end_of_list. >> input
echo  >> input
cat to-prove >> input
prover9 -f input
