# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import os

from auth import *
from init import *

import hashlib

RS = "iisc.iudx.org.in"
if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
    RS = "localhost"

TUPLE = type(("x",))

policy = "x can access *" # dummy policy
provider.set_policy(policy)

policy = 'all can access * for 2 hours if tokens_per_day < 100'
provider.set_policy(policy)

assert policy == provider.get_policy()['response']['policy']

r = provider.audit_tokens(5)
assert r['success'] == True
audit_report        = r['response']
as_provider         = audit_report["as-provider"]

num_tokens_before = len(as_provider)

body = [
	{
		"resource-id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS+ "/resource-xyz-yzz",
		"api"		: "/latest",
		"methods"	: ["GET"],
		"body"		: {"key":"some-key"}
	},
	{
		"resource-id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz"
	}
]

r = consumer.get_token(body)
access_token = r['response']

assert r['success']     == True
assert None             != access_token
assert 7200             == access_token['expires-in']

token = access_token['token'],

if type(token) == TUPLE:
	token = token[0]

s = token.split("/")

assert len(s)	== 3
assert s[0]	== 'auth.iudx.org.in'


server_token = access_token['server-token'][RS]
if type(server_token) == TUPLE:
	server_token = server_token[0]

assert True  == resource_server.introspect_token (token,server_token)['success']
assert False == resource_server.introspect_token (token,'invalid-token-012345678901234567')['success']
assert False == resource_server.introspect_token (token)['success']

r = provider.audit_tokens(5)
assert r["success"] == True
audit_report = r['response']
as_provider = audit_report["as-provider"]

num_tokens_after = len(as_provider)

# number of tokens before and after request by consumer
assert num_tokens_after > num_tokens_before

token_hash = hashlib.sha256(token.split("/")[2]).hexdigest()

print "Token_hash",token_hash

token_hash_found = False
found = None
for a in as_provider:
	if a['token-hash'] == token_hash:
		token_hash_found = True
                found = a
		break

assert token_hash_found	== True
print "Found 1",found
assert found['revoked'] == False
r = provider.revoke_token_hashes(token_hash)
assert True == r['success']
print "after revoke",r

r = provider.audit_tokens(5)
assert r["success"] == True
audit_report = r['response']
as_provider = audit_report["as-provider"]

token_hash_found = False
found = None
for a in as_provider:
	if a['token-hash'] == token_hash:
		token_hash_found = True
                found = a
		break

print "Found",found

assert found['revoked'] == True

