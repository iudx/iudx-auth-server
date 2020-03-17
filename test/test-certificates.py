# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from auth import *
from init import *

r = resource_server.certificate_info()
assert r["success"] == True
assert r["response"]["certificate-class"] == 1

r = consumer.certificate_info()
assert r["success"] == True
assert r["response"]["certificate-class"] == 2

r = provider.certificate_info()
assert r["success"] == True
assert r["response"]["certificate-class"] == 3
