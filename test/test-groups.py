# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from auth import *
from init import *

r                       = provider.delete_consumer_from_group("*","confidential")
assert r["success"]     == True

r       		= provider.list_group("confidential")
assert r["success"]     == True
assert 0		== len(r["response"])

provider.add_consumer_to_group("barun@iisc.ac.in","confidential",100)
provider.add_consumer_to_group("xyz@iisc.ac.in","confidential",100)

r                       = provider.list_group("confidential")
assert r["success"]     == True

m1_found = False;
m2_found = False;

members = r["response"]

for m in members:
#
	if m['consumer'] == 'barun@iisc.ac.in':
		m1_found = True

	elif m['consumer'] == 'xyz@iisc.ac.in':
		m2_found = True
#

assert m1_found == True and m2_found == True

r                       = provider.delete_consumer_from_group("barun@iisc.ac.in","confidential")
assert r["success"]     == True

r                       = provider.list_group("confidential")
assert r["success"]     == True
assert 1		== len(r["response"])
assert "xyz@iisc.ac.in"	== r["response"][0]['consumer']

r                       = provider.delete_consumer_from_group("xyz@iisc.ac.in","confidential")
assert r["success"]     == True

r		        = provider.list_group("confidential")
assert r["success"]     == True
assert 0		== len(r["response"])

provider.set_policy('all can access iisc.iudx.org.in/resource-xyz* if consumer-in-group(xyz,confidential)')

body = {
	"resource-id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/iisc.iudx.org.in/resource-xyz-yzz",
}

provider.add_consumer_to_group("barun@iisc.ac.in","confidential",100)

r       		= provider.list_group("confidential")
assert r["success"]     == True
assert 1		== len(r["response"])

assert True     == consumer.get_token(body)["success"]
assert True     == provider.delete_consumer_from_group("barun@iisc.ac.in","confidential")["success"]
assert False    == consumer.get_token(body)["success"]
