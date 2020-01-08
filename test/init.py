from auth import *

consumer		= Auth("consumer.pem","private-key.pem")
provider		= Auth("provider.pem","private-key.pem")
resource_server		= Auth("r-server.pem","private-key.pem")
fake_resource_server	= Auth("f-server.pem","private-key.pem")
