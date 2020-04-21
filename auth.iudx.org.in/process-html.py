import re
import sys

f="file.c.html"

f = open("file.c.html")
d = f.read().split("\n")
f.close()

for l in d:

	l = l.replace("1em","1.1em")

	l = re.sub(r'\$HTTPS\$([^\s]+)',r'<a style="color:#F4D03F" href=https://\g<1>>https://\g<1></a>',l)
	l = re.sub(r'\$HTTP\$([^\s]+)',r'<a style="color:#F4D03F" href=http://\g<1>>http://\g<1></a>',l)


	l = l.replace('<span class="Statement">Warning</span>','<span class="Statement"><font color=red>Warning</font></span>') 

	#l = re.sub('\t<span class="Statement">(.*)</span>',r'\t<span class="Statement"><font color=red>\1</font></span>',l) 

	if l.startswith("<title>"):
		l = "<title>IUDX Auth API documentation - /" + sys.argv[1] + "</title>"

	if l.startswith("*") and l.endswith("*"):
		l = "<b>" + l[1:][:-1] + "</b>"

	stripped = l.strip()

	l = l.replace("_xxx_"," ")

	print l

