# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os

from init import consumer 
from init import provider 
from init import resource_server

RS = "iisc.iudx.org.in"
if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
    RS = "localhost"

policy = "x can access *" # dummy policy
r = consumer.set_policy(policy)
assert r['success']	is False
assert r['status_code'] == 403 

token 		= {}
server_token	= {}

r = consumer.introspect_token (token,server_token)
assert r['success']	is False
assert r['status_code'] == 403 

r = provider.introspect_token (token,server_token)
assert r['success']	is False
assert r['status_code'] == 403 
