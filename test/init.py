# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
from auth import *

auth_server = "auth.iudx.org.in"
home = os.path.expanduser("~") + "/"

if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
#
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    auth_server = "localhost"
    resource_server = Auth("l-server.pem", home + "l-server.key.pem", auth_server)
#
else:
#
    resource_server = Auth("r-server.pem", home + "r-server.key.pem", auth_server)
#

consumer		= Auth("consumer.pem", home + "consumer.pem", auth_server)
provider		= Auth("provider.pem", home + "provider.pem", auth_server)
fake_resource_server	= Auth("f-server.pem", home + "f-server.pem", auth_server)
