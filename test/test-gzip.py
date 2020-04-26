import os
import requests

home = os.path.expanduser("~") + "/"

verify = True
if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
#
	verify = False
#

response = requests.get (
	url	= "https://auth.iudx.org.in/topup.html", 
	verify	= verify,
	cert	= (home + "provider.pem", home + "provider.key.pem"),
)

print "Got content encoding as :" + response.headers["Content-Encoding"]
