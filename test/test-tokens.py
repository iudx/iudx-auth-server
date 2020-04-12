# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os

from init import consumer 
from init import provider 
from init import resource_server

from init import restricted_consumer 

import hashlib

RS = "iisc.iudx.org.in"

TUPLE = type(("x",))

policy = "x can access *" # dummy policy
provider.set_policy(policy)

policy = 'all can access * for 2 hours if tokens_per_day < 100'
provider.set_policy(policy)

assert policy == provider.get_policy()['response']['policy']

new_policy  = "*@rbccps.org can access resource-yyz-abc for 1 hour"
assert provider.append_policy(new_policy)['success'] is True

updated_policy = policy + ';' + new_policy
assert updated_policy == provider.get_policy()['response']['policy']

r = provider.audit_tokens(5)
assert r['success'] is True
audit_report        = r['response']
as_provider         = audit_report["as-provider"]


num_tokens_before = len(as_provider)
body = [
	{
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
		"api"		: "/latest",
		"methods"	: ["GET"],
		"body"		: {"key":"some-key"}
	},
	{
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/abc.com/abc-xyz"
	}
]

r = consumer.get_token(body)
access_token = r['response']

assert r['success']     is True
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

assert resource_server.introspect_token (token,server_token)['success'] is True
# introspect once more
assert resource_server.introspect_token (token,server_token)['success'] is True

# introspect with request
request = [
            {
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
		"apis"		: ["/latest"],
		"methods"	: ["GET"],
		"body"		: {"key":"some-key"}
	    }   
]

bad_request = [
            {
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/" + RS + "/resource-xyz-yzz",
		"apis"		: ["/latest-now"],
		"methods"	: ["POST"],
		"body"		: {"key":"some-key"}
	    }   
]

assert resource_server.introspect_token (token,server_token,request)['success']			is True
assert resource_server.introspect_token (token,server_token,bad_request)['success']		is False

assert resource_server.introspect_token (token,'invalid-token-012345678901234567')['success']	is False
assert resource_server.introspect_token (token)['success']					is False

r = provider.audit_tokens(5)
assert r["success"] is True
audit_report = r['response']
as_provider = audit_report["as-provider"]
num_tokens_after = len(as_provider)

# number of tokens before and after request by consumer
assert num_tokens_after > num_tokens_before

token_hash = hashlib.sha256(token).hexdigest()

token_hash_found = False
found = None

for a in as_provider:
	if a['token-hash'] == token_hash:
		token_hash_found = True
		found = a
		break

assert token_hash_found	is True
assert found['revoked'] is False
assert provider.revoke_token_hashes(token_hash)['success'] is True

# check if token was revoked
r = provider.audit_tokens(5)
assert r["success"] is True
audit_report = r['response']
as_provider = audit_report["as-provider"]

token_hash_found = False
found = None
for a in as_provider:
	if a['token-hash'] == token_hash:
		token_hash_found = True
		found = a
		break


assert token_hash_found	is True
assert found['revoked'] is True

# test revoke-all (as provider)
r = provider.get_token(body)
access_token = r['response']

assert r['success']     is True
assert None             != access_token
assert 7200             == access_token['expires-in']

token = access_token['token']

if type(token) == TUPLE:
	token = token[0]

s = token.split("/")

assert len(s)	== 3
assert s[0]	== 'auth.iudx.org.in'

r = provider.audit_tokens(100)
assert r["success"] is True
audit_report        = r['response']
as_provider         = audit_report["as-provider"]
num_tokens          = len(as_provider)
assert num_tokens   >= 1

for a in as_provider:
        if a["revoked"] is False and a['expired'] is False:
                cert_serial         = a["certificate-serial-number"]
                cert_fingerprint    = a["certificate-fingerprint"]
                break

r = provider.revoke_all(cert_serial, cert_fingerprint)
assert r["success"] is True
assert r["response"]["num-tokens-revoked"] >= 1

r = provider.audit_tokens(100)
assert r["success"] is True
audit_report        = r['response']
as_provider         = audit_report["as-provider"]

for a in as_provider:
	if a['certificate-serial-number'] == cert_serial and a['certificate-fingerprint'] == cert_fingerprint:
                if a['expired'] is False:
                        assert a['revoked'] is True

# test revoke API
r = provider.get_token(body)
access_token = r['response']

assert r['success']     is True
assert None             != access_token
assert 7200             == access_token['expires-in']

token = access_token['token']

if type(token) == TUPLE:
	token = token[0]

s = token.split("/")

assert len(s)	== 3
assert s[0]	== 'auth.iudx.org.in'

r = provider.audit_tokens(5)
assert r["success"] is True
audit_report        = r['response']
as_consumer         = audit_report["as-consumer"]
num_revoked_before  = 0

for a in as_consumer:
        if a['revoked'] is True:
                num_revoked_before = num_revoked_before + 1

assert provider.revoke_tokens(token)["success"] is True

r = provider.audit_tokens(5)
assert r["success"] is True
audit_report        = r['response']
as_consumer         = audit_report["as-consumer"]
num_revoked_after   = 0

for a in as_consumer:
        if a['revoked'] is True:
                num_revoked_after = num_revoked_after + 1

assert num_revoked_before < num_revoked_after

new_policy  = "*@iisc.ac.in can access * for 1 hour"
assert provider.set_policy(new_policy)['success'] is True

body = [
	{
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
	},
	{
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r2"
	}
]

r = restricted_consumer.get_token(body)
access_token = r['response']

assert r['success']     is True 
assert None             != access_token

body = [
	{
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1/r1",
	},
	{
		"id"	: "rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs2/r2"
	}
]

r = restricted_consumer.get_token(body)
assert r['success']	is False 
assert r['status_code']	== 401
