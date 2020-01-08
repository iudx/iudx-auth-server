# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from auth import *
from init import *

import hashlib

TUPLE = type(("x",))

policy = "x can access *" # dummy policy
provider.set_policy(policy)

policy = 'all can access * for 2 hours if country = "IN"'
provider.set_policy(policy)

assert policy == provider.get_policy()[1]['policy']

[ret, audit_report]= provider.audit_tokens(5)
assert ret == "success"
as_provider = audit_report["as-resource-owner"]

num_tokens_before = len(as_provider)

body = [
	{
		"resource-id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/iisc.iudx.org.in/resource-xyz _yzz",
		"api"		: "/latest",
		"methods"	: ["GET"],
		"body"		: {"key":"some-key"}
	},
	{
		"resource-id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc_ xyz"
	}
]

access_token = consumer.get_token(body)[1]

assert None != access_token
assert 7200 == access_token['expires-in']

token = access_token['token'],

if type(token) == TUPLE: 
	token = token[0]

s = token.split("/")

assert len(s)	== 3
assert s[0]	== 'auth.iudx.org.in'


server_token = access_token['server-token']['iisc.iudx.org.in'] 
if type(server_token) == TUPLE: 
	server_token = server_token[0]

assert "success"	== resource_server.introspect_token (token,server_token)[0]
assert "failed"		== resource_server.introspect_token (token,"invalid-token-012345678901234567")[0]
assert "failed"		== resource_server.introspect_token (token)[0]

[ret, audit_report]= provider.audit_tokens(5)
assert ret == "success"
as_provider = audit_report["as-resource-owner"]

num_tokens_after = len(as_provider)

# number of tokens before and after request by consumer
assert num_tokens_after > num_tokens_before

token_hash = hashlib.sha256(token.split("/")[2]).hexdigest()

token_hash_found = False
for a in as_provider:
	if a['token-hash'] == token_hash:
		token_hash_found = True
		break

assert token_hash_found	== True
assert "success"	== provider.revoke_token_hashes(token_hash)[0]
