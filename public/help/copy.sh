for src in `find . -name "*.txt" | sed 's/^.\///'`
do
	dst=`echo $src | sed 's/\//-/g'`
	cp $src "/var/www/htdocs/$dst"
done
