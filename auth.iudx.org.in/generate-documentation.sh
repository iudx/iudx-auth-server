#!/bin/sh

for f in `ls *.txt`
do
	cp $f file.c

	python2 ./process-txt.py > tmp
	mv tmp file.c

	vim -c 'colorscheme delek' -c TOhtml -c wqa file.c

	api=`cat acl-set.txt | grep -a2 Endpoint: | tail -1 |  cut -f4- -d'/'`

	python2 ./process-html.py "$api" > tmp

	ff=`echo $f | cut -f1 -d'.'`

	mv tmp $ff.html
done
