# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import os
import sys
import json
import requests

class Auth():
#{
	def __init__(self, certificate, key, auth_server="auth.iudx.org.in", version=1):
	#
		self.ssl_verify = True
 
		if "AUTH_SERVER" in os.environ and os.environ["AUTH_SERVER"] == "localhost":
			self.ssl_verify = False

		self.url		= "https://" + auth_server + "/auth/v" + str(version)
		self.credentials	= (certificate, key)
	#

	def call(self, api, body=None):
	#
		ret = True # success

		body = json.dumps(body)

		response = requests.post (
			url	= self.url + "/" + api,
			verify	= self.ssl_verify,
			cert	= self.credentials,
			data	= body,
			headers	= {"content-type":"application/json"}
		)

		if response.status_code != 200:
		#
			sys.stderr.write (
				"WARNING: auth API failure  | "	+
				self.url + "/" + api	+ " | "	+
				response.reason 	+ " | "	+
				response.text
			)

			ret = False
		#

		if response.headers['content-type'] == 'application/json':
			return {
				"success"	: ret,
				"response"	: json.loads(response.text),
				"status_code"	: response.status_code
			}
		else:
		#
			sys.stderr.write (
				"WARNING: auth did not send 'application/json'"
			)

			return {"success":ret, "response":None}
		#
	#

	def certificate_info(self):
		return self.call("certificate-info")

	def get_token(self, request, token_time=None, existing_token=None):
	#
		body = {'request': request}

		if token_time:
			body['token-time'] = token_time

		if existing_token:
			body['existing-token'] = existing_token

		return self.call("token", body)
	#

	def get_policy(self):
		return self.call("acl")

	def set_policy(self, policy):
		body = {'policy': policy}
		return self.call("acl/set", body)

	def revert_policy(self):
		return self.call("acl/revert")

	def append_policy(self, policy):
		body = {'policy': policy}
		return self.call("acl/append", body)

	def introspect_token(self, token, server_token=None, request=None):
	#
		body = {'token': token}

		if server_token:
			body['server-token'] = server_token

		if request:
			if type(request) is type([]):
				body['request'] = request
			else:
				body['request'] = [request]

		return self.call("token/introspect", body)
	#

	def revoke_tokens(self, tokens):
	#
		if type(tokens) is type([]):
			body = {'tokens': tokens}
		else:
			body = {'tokens': [tokens]}

		return self.call("token/revoke", body)
	#

	def revoke_token_hashes(self, token_hashes):
	#
		if type(token_hashes) is type([]):
			body = {'token-hashes': token_hashes}
		else:
			body = {'token-hashes': [token_hashes]}

		return self.call("token/revoke", body)
	#

	def revoke_all(self, cert_serial, cert_fingerprint):
		body = {'serial' : cert_serial, 'fingerprint' : cert_fingerprint}
		return self.call("token/revoke-all", body)

	def audit_tokens(self, hours):
		body = {'hours': hours}
		return self.call("audit/tokens", body)

	def add_consumer_to_group(self, consumer, group, valid_till):
		body = {'consumer': consumer, 'group': group, 'valid-till' : valid_till}
		return self.call("group/add", body)

	def delete_consumer_from_group(self, consumer, group):
		body = {'consumer': consumer, 'group': group}
		return self.call("group/delete", body)

	def list_group(self, consumer, group=None):
	#
		body = {'consumer': consumer}

		if group:
			body['group'] = group

		return self.call("group/list", body)
	#

	############################# Marketplace ##############################

	def topup(self, amount, serial = None, fingerprint = None):
	#
		body = {'amount': amount}

		if serial and fingerprint:
			body['serial']		= serial
			body['fingerprint']	= fingerprint 

		return self.call("marketplace/topup", body)
	#
#}
