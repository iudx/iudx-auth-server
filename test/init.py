import os
from auth import *

private_key = os.path.expanduser("~") + "/private-key.pem"

consumer		= Auth("consumer.pem",private_key)
provider		= Auth("provider.pem",private_key)
resource_server		= Auth("r-server.pem",private_key)
fake_resource_server	= Auth("f-server.pem",private_key)
