#!/bin/sh

for f in `ls *.txt`
do
	cp $f file.c

	python2 ./process-txt.py > tmp
	mv tmp file.c

	vim -c 'colorscheme delek' -c TOhtml -c wqa file.c

	python2 ./process-html.py > tmp

	ff=`echo $f | cut -f1 -d'.'`

	mv tmp $ff.html
done
