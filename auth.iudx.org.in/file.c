
*Request for an access token*
*---------------------------*

Endpoint:

	$HTTPS$<auth-server>/auth/v1/token

Description:

	This API is used to request an access token from the Auth server.
	The "token" can then be used to get data from a resource server.

Called_xxx_by:

	A "data consumer" with a valid class-2 or above certificate.

Methods:

	POST

Headers:

	content-type : "application/json"

	Please note that "text/plain" can also be used to avoid CORS issues.

Body_xxx_in_xxx_JSON_xxx_format:

	{
		"request" : {											// required
			"id"		: <a resource id for which access is requested>,			// required
			"apis"		: <a list of APIs a consumer wishes to access on the resource id>	// optional
			"methods"	: <a list of methods a consumer wishes to call on the APIs>		// optional
			"body"		: <a dictionary of body variables to be called with the API>		// optional
		},

		"token-time"		: <the time in seconds, till which the token should be valid>		// optional
		"existing-token"	: <a valid token a data consumer already has>				// optional
	}

	The 'request' field may also be an array of objects.

	The "existing-token" header field is used to indicate that new token
	should NOT be created; i.e. the existing token will be used to access
	the new requested list of resource ids.

	The_xxx_'request'_xxx_fields_xxx_are:

	1._xxx_id:

		The "id" is the identifer of the resource (a data-set) the consumer is interested in accessing.

		Data consumers are not expected to create these "ids" themselves;
		but are expected to get these "id"s from a catalogue server.

		An example catalog server is: $HTTPS$varanasi.iudx.org.in

		And_xxx_an_xxx_example_xxx_query_xxx_to_xxx_get_xxx_ids_xxx_is:
			$HTTPS$varanasi.iudx.org.in/catalogue/v1/search?item-type=resourceItem

		The_xxx_resource_xxx_'id'_xxx_consists_xxx_of_xxx_at_xxx_least_xxx_4_xxx_parts_xxx_seperated_xxx_by_xxx_a_xxx_'/'_xxx_indicating:

			1. The email domain of the data provider.

			2. SHA-1 hash of the data provider's email-id (to mask the provider's email).

			3. The hostname (FQDN) of the resource server where the resource is hosted.

			4. The name of the resource (which may contain additional '/'s).

		For example: example.com/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.com/resource-name

	2._xxx_apis:

		The 'apis' is the set of APIs a consumer wants to access on a 'id'.
		Instead of 'apis', just 'api' (a string) could also be used.

		For example: ["/latest", "/query"]
		As the field is optional, the default value of 'apis' is: ["/*"]

	3._xxx_methods:

		The 'methods' is the set of methods a consumer wants to access on an 'api'.
		Instead of 'methods', just 'method' (a string) could also be used.

		For example: ["GET", "POST"]
		As the field is optional, the default value of 'apis' is: ["*"]

	4._xxx_body:

		The body indicates the JSON body to be passed with the 'apis'.

		For example: {"operation" : "select", "on" : "all"}
		As the field is optional, the default value of 'body' is: null


HTTP_xxx_response_xxx_code:

	200
		If access is allowed.

	403
		If access is denied.

	429
		If the client makes too many requests.

Using_xxx_pyIUDX_xxx_SDK:

	from pyIUDX.auth import auth

	iudx_auth = auth.Auth("certificate.pem","private-key.pem")

	request = [
		{"id": "example.com/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.com/r1"},
		{"id": "example.com/5332dabcd033fffca0a3332abcdefe7a143a109c/rs.com/r2"}
	]

	iudx_auth.get_token(request)

CURL_xxx_examples:

	1. Requesting token for data from a single resource server

		Request:

			curl -XPOST $HTTPS$auth.iudx.org.in/auth/v1/token

			--cert certificate.pem --key private-key.pem

			-H 'content-type: application/json'

			-d '{
				"request" : [
					{"id": "example.com/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs.com/r1"},
					{"id": "example.com/5332dabcd033fffca0a3332abcdefe7a143a109c/rs.com/r2"}
				]
			}'

		Response:

			200 OK
			content-type : "application/json"

			{
				"token"	: "auth.iudx.org.in/user@domain.com/2204adcbc990ffff234689aaabcdef90",
				"token-type"	: "IUDX",
				"expires-in"	: 3600
			}

		Response_xxx_fields:

		1. token
			Is the access token required to access data from a resource server
			(rs.com in this case), and is in the format: 'auth-server/consumer/random-bytes'

			A_xxx_valid_xxx_IUDX_xxx_token_xxx_consist_xxx_of_xxx_3_xxx_fields_xxx_(delimited_xxx_by_xxx_'/'):

				1. Who has issued the token (The Auth server)
				2. To whom the token has been issued (The consumer)
				3. Random string

			In_xxx_the_xxx_above_xxx_example:
				token = "auth.iudx.org.in/user@domain.com/2204adcbc990ffff234689aaabcdef90"

		2. expires-in
			Indicates how long the token is valid in seconds.

	2. Requesting token for data from multiple resource servers

		Request:

			curl -XPOST $HTTPS$auth.iudx.org.in/auth/v1/token

				--cert certificate.pem --key private-key.pem

				-H 'content-type: application/json'

				-d '{
					"request" : [
						{"id": "example.com/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs1.com/r1"}
						{"id": "example.com/9cf2c2382cf661fc20a4776345a3be7a143a109c/rs2.com/r2"}
					]
				}'
		Response:

			200 OK
			content-type : "application/json"

			{
				"token"	: "auth.iudx.org.in/user@domain.com/1802a84d157ff4d113150aeca8bdacee",
				"token-type"	: "IUDX",
				"expires-in"	: 3600,
				"server-token"	: {
					"rs1.com" : "rs1.com/91834abcd323924339ab",
					"rs2.com" : "rs2.com/52338cdfff3222699900"
				}
			}

		Other_xxx_response_xxx_fields:

			3. server-token

				The "server-token" field is sent only if the request body
				contains id's from multiple resource servers

				In_xxx_this_xxx_example:
					"rs1.com" and "rs2.com"

				In the above example, when requesting data from a resource server,
				the consumer must also provide the "server-token" of the respective resource server,
				along with the consumer's "token".

				In_xxx_the_xxx_above_xxx_example:
					token = "auth.iudx.org.in/user@domain.com/1802a84d157ff4d113150aeca8bdacee"

				and_xxx_the_xxx_"server-token"_xxx_when_xxx_a_xxx_consumer_xxx_requests_xxx_data_xxx_from:_xxx_

					"rs1.com" is "rs1.com/91834abcd323924339ab",
							and
					"rs2.com" is "rs2.com/52338cdfff3222699900"

				The "server-token" ensures that only a genuine resource server can access its token.

				NOTE:

				The "server-token"s may change if "existing-token" is used with
				multiple resource servers. Hence, consumers must update their
				"server-token"s as in the API response.

See_xxx_also:

	token_xxx_introspect_xxx_API:
		$HTTP$auth.iudx.org.in/token-introspect.html

	token_xxx_revoke_xxx_API:
		$HTTP$auth.iudx.org.in/token-revoke.html

	token_xxx_revoke_xxx_all_xxx_API:
		$HTTP$auth.iudx.org.in/token-revoke-all.html


