# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os

from init import provider 
from init import provider 
from init import resource_server

RS = "iisc.iudx.org.in"
if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
	RS = "localhost"

policy = "x can access *" # dummy policy
provider.set_policy(policy)

invalid_policy = "invalid policy *"
assert provider.set_policy(invalid_policy)['success'] is False

assert policy == provider.get_policy()['response']['policy']

invalid_policy = "invalid policy *"
assert provider.append_policy(invalid_policy)['success'] is False

assert policy == provider.get_policy()['response']['policy']

