import sys

ignore = ["Host:", "User-Agent:", "Accept:", "Content-Length:", "x-xss-protection:", "strict-transport-security:", "x-content-type-options:", "Date:", "Connection:", "x-frame-options:", "x-xss-protection:", "x-frame-options:", "x-content-type-options:", "access-control-allow-headers:", "access-control-allow-methods:", "access-control-allow-origin:", "strict-transport-security:", "connection:"]

for line in sys.stdin:

	found = False
	for i in ignore:

		if i in line:
			found = True
			break

	if not found:
		print line
    		
