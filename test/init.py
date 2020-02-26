# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
from auth import *

private_key = os.path.expanduser("~") + "/private-key.pem"

auth_server = "auth.iudx.org.in"
if environ["SERVER"] == "localhost":
        auth_server = "127.0.0.1"
        resource_server	= Auth("r-server-localhost.pem", private_key, auth_server)
else:
        resource_server	= Auth("r-server.pem", private_key, auth_server)

if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
#
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    auth_server = "localhost"
#

private_key = os.path.expanduser("~") + "/private-key.pem"

consumer		= Auth("consumer.pem", private_key, auth_server)
provider		= Auth("provider.pem", private_key, auth_server)
resource_server		= Auth("r-server.pem", private_key, auth_server)
localhost               = Auth("l-server.pem",private_key, auth_server)
fake_resource_server	= Auth("f-server.pem", private_key, auth_server)
