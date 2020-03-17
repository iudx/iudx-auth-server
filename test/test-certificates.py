# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from auth import *
from init import *

r = resource_server.certificate_info()
assert r["success"] == True
assert r["response"]["certificate-class"] == 1
assert r["response"]["id"] == "arun.babu@rbccps.org" 

r = consumer.certificate_info()
assert r["success"] == True
assert r["response"]["certificate-class"] == 2
assert r["response"]["id"] == "barun@iisc.ac.in" 

r = provider.certificate_info()
assert r["success"] == True
assert r["response"]["certificate-class"] == 3
assert r["response"]["id"] == "example@example.com" 
