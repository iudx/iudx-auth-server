# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from init import consumer 
from init import provider 
from init import resource_server

r = resource_server.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 1
assert r["response"]["id"] == "example@example.com" 

r = consumer.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 2
assert r["response"]["id"] == "barun@iisc.ac.in" 

r = provider.certificate_info()
assert r["success"] is True
assert r["response"]["certificate-class"] == 3
assert r["response"]["id"] == "arun.babu@rbccps.org"

# delegated certificate cannot call any Auth API
r = delegate.certificate_info()
assert r["success"] is False
