
echo ""
echo "Performing .trace file analysis"

cd traces 

	for f in `ls *.trace | sort -n`
	do
	    echo "Analysing $f"
		cat $f | curl-trace-parser --blueprint | python ../filter.py > tmp
		head -1 tmp >> ../all.apib
		cat $f.info >> ../all.apib 
		cat tmp | grep -v '#' >> ../all.apib
	done

cd ..

dos2unix -q all.apib

mkdir -p output

echo ""
echo "Generating HTML output"

aglio -i all.apib --theme-template triple -o output/auth-api-doc.html
sed -i -e 's/API Documentation/IUDX-Auth API-Documentation/' output/auth-api-doc.html
cp output/auth-api-doc.html ../doc.html

echo "Generating swagger-auth-api.json"
apib2swagger -i all.apib -o output/swagger-auth-api.json
cp output/swagger-auth-api.json ../swagger.json

sed -i -e 's/API Documentation/IUDX-Auth API Documentation \(\<a href=\"swagger.json\"\>swagger.json\<\/a>\)/' output/auth-api-doc.html

rm -rf traces && rm all.apib && rm result*

echo         "================================================================  END  =============================================================="

echo	     "NOTE: Find the output in output/ directory"
