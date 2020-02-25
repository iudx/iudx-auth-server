import os
from auth import *

private_key = os.path.expanduser("~") + "/private-key.pem"

auth_server = "auth.iudx.org.in"
if environ["SERVER"] == "localhost":
        auth_server = "127.0.0.1"
consumer		= Auth("consumer.pem", private_key, auth_server)
provider		= Auth("provider.pem", private_key, auth_server)
resource_server		= Auth("r-server.pem", private_key, auth_server)
fake_resource_server	= Auth("f-server.pem", private_key, auth_server)
