import os
from auth import *

private_key = os.path.expanduser("~") + "/private-key.pem"
auth_server = "auth.iudx.org.in"

consumer		= Auth("consumer.pem", private_key, auth_server)
provider		= Auth("provider.pem", private_key, auth_server)
resource_server		= Auth("r-server.pem", private_key, auth_server)
fake_resource_server	= Auth("f-server.pem", private_key, auth_server)
