# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
from auth import Auth 

auth_server = "auth.iudx.org.in"
home        = os.path.expanduser("~") + "/"

if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
#
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    resource_server = Auth(home + "l-server.pem", home + "l-server.key.pem", auth_server)
#
else:
#
    resource_server = Auth("r-server.pem", home + "r-server.key.pem", auth_server)
#

consumer		= Auth(home + "consumer.pem",	home + "consumer.key.pem",	auth_server)
provider		= Auth(home + "provider.pem",	home + "provider.key.pem",	auth_server)
delegate		= Auth(home + "delegated.pem",	home + "delegated.key.pem",	auth_server)
restricted_consumer	= Auth(home + "restricted.pem",	home + "restricted.key.pem",	auth_server)
fake_resource_server	= Auth(home + "f-server.pem",	home + "f-server.key.pem",	auth_server)
