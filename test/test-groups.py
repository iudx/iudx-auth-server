# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from auth import *
from init import *

assert "success"	== provider.delete_consumer_from_group("*","confidential")[0]

[ret, members]		= provider.list_group("confidential")
assert "success"	== ret
assert 0		== len(members)

provider.add_consumer_to_group("barun@iisc.ac.in","confidential",100)
provider.add_consumer_to_group("xyz@iisc.ac.in","confidential",100)

[ret, members]		= provider.list_group("confidential")
assert "success"	== ret

m1_found = False;
m2_found = False;

for m in members:
#
	if m['consumer'] == 'barun@iisc.ac.in':
		m1_found = True 

	elif m['consumer'] == 'xyz@iisc.ac.in':
		m2_found = True 
#

assert m1_found == True and m2_found == True

assert "success"	== provider.delete_consumer_from_group("barun@iisc.ac.in","confidential")[0]

[ret, members]		= provider.list_group("confidential")
assert "success"	== ret
assert 1		== len(members)
assert "xyz@iisc.ac.in"	== members[0]['consumer']

assert "success"	== provider.delete_consumer_from_group("xyz@iisc.ac.in","confidential")[0]

[ret, members]		= provider.list_group("confidential")
assert "success"	== ret
assert 0		== len(members)

provider.set_policy('all can access iisc.iudx.org.in/resource-xyz* if consumer-in-group(xyz,confidential)')

body = {
	"resource-id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/iisc.iudx.org.in/resource-xyz _yzz",
}

provider.add_consumer_to_group("barun@iisc.ac.in","confidential",100)

[ret, members]		= provider.list_group("confidential")
assert "success"	== ret
assert 1		== len(members)

assert "success"	== consumer.get_token(body)[0]
assert "success"	== provider.delete_consumer_from_group("barun@iisc.ac.in","confidential")[0]
assert "failed"		== consumer.get_token(body)[0]
