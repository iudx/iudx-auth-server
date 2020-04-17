f = open("file.c")
d = f.read().split("\n")
f.close()

d[1] = "*" + d[1] + "*" 
d[2] = "*" + d[2] + "*" 

for l in d:
	l = l.replace("http://","$HTTP$")
	l = l.replace("https://","$HTTPS$")

	stripped = l.strip()
	if stripped.endswith(":"):
		l = l.replace(" ","_xxx_")
	
	print l
