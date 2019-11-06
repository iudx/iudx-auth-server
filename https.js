/*
 * Copyright (c) 2019
 * Arun Babu {arun <dot> hbni <at> gmail}
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

"use strict";

const fs		= require('fs');
const os		= require('os');
const dns 		= require('dns');
const url		= require('url');
const cors		= require('cors');
const Pool		= require('pg').Pool;
const https		= require('https');
const chroot		= require('chroot');
const crypto		= require('crypto');
const logger		= require('node-color-log');
const cluster		= require('cluster');
const express		= require('express');
const aperture		= require('./node-aperture');
const geoip_lite	= require('geoip-lite');
const bodyParser	= require('body-parser');
const http_sync_request	= require('sync-request');
const pgNativeClient 	= require('pg-native');
const pg		= new pgNativeClient();

const TOKEN_LENGTH	= 16;
const TOKEN_LENGTH_HEX	= 2*TOKEN_LENGTH;

const is_openbsd	= os.type() === 'OpenBSD';
const WORKER_PLEDGE	= "stdio tty prot_exec inet dns recvfd rpath proc exec";

var pledge;
var unveil;

if (is_openbsd)
{
	pledge	= require("node-pledge");
	unveil	= require("openbsd-unveil");
}

const OUR_NAME		= 'auth.iudx.org.in';
const CRL_SCAN_TIME	= 300; // seconds

const EUID = process.geteuid();

var CRL;
var CRL_last_accessed = new Date(2000,1,2,3,4,5,6);

dns.setServers([
  '1.1.1.1',
  '4.4.4.4',
  '8.8.8.8',
  '[2001:4860:4860::8888]',
]);

function log(color, msg)
{
	logger.color(color).log(new Date() + " | " + msg);
}

var do_drop_privilege = true;
const argv = process.argv.slice(2);

if (argv.length < 1)
{
	log("green", "Starting Server in production mode");
}
else if (argv.length > 1)
{
	log("red", "Please provide only one argument. Exiting process!!!");
	process.exit(0);
}
else
{
	if (argv[0] === "test")
	{
		log("yellow", "Starting Server in development mode");
		do_drop_privilege = false;
	}
	else
	{
		log("red","Valid arguments are: 'test' and 'start' with npm");
		process.exit(0);
	}
}

var db_password = fs.readFileSync ('db.password','ascii').trim();

const pool = new Pool ({
	host		: '127.0.0.1',
	port		: 5432,
	user		: 'auth',
	database	: 'postgres',
	password	: db_password,
});

pool.connect();

pg.connectSync (
	'postgresql://auth:'+ db_password+ '@127.0.0.1:5432/postgres',
		function(err) {
			if(err) throw err;
		}
);

var app = express();
app.use (
	cors ({
		methods		: ['POST','GET'],
		credentials	: true,
		origin		: function (origin, callback) {
			callback(null, true);
		}
	})
);
app.use(bodyParser.json());
app.use(bodyParser.text());
app.disable('x-powered-by');

app.get('/', function (req, res) {
	res.sendFile(__dirname + '/public/hyperspace/index.html');
});

app.get('/apis', function (req, res) {
	res.sendFile(__dirname + '/public/help/apis.html');
});

app.get('/favicon.ico', function (req, res) {
	res.sendFile(__dirname + '/public/favicon.ico');
});

app.get('/doc', function (req, res) {
	res.sendFile(__dirname + '/public/output/auth-api-doc.html');
});

app.use("/assets", express.static(__dirname + "/public/hyperspace/assets"));
app.use("/images", express.static(__dirname + "/public/hyperspace/images"));

const apertureOpts = {

    types: aperture.types,
    typeTable: {

        ip				: 'ip',
	time				: 'time',

	tokens_per_day			: 'number',	// tokens issued today

	api				: 'string',	// the API to be called
	method				: 'string',	// the method on the API

	'cert.class'			: 'number',	// the certificate class
	'cert.cn'			: 'string',
	'cert.o'			: 'string',
	'cert.ou'			: 'string',
	'cert.c'			: 'string',
	'cert.st'			: 'string',
	'cert.gn'			: 'string',
	'cert.sn'			: 'string',
	'cert.title'			: 'string',

	'cert.issuer.cn'		: 'string',
	'cert.issuer.email'		: 'string',
	'cert.issuer.o'			: 'string',
	'cert.issuer.ou'		: 'string',
	'cert.issuer.c'			: 'string',
	'cert.issuer.st'		: 'string',

	groups				: 'string',	// CSV actually

	country				: 'string',
	region				: 'string',
	timezone			: 'string',
	city				: 'string',
	latitude			: 'number',
	longitude			: 'number',
    }
};

const parser	= aperture.createParser		(apertureOpts);
const evaluator	= aperture.createEvaluator	(apertureOpts);

const https_options = {
	key:			fs.readFileSync('key.pem'),
	cert:			fs.readFileSync('server.pem'),
	ca:			fs.readFileSync('ca.iudx.org.in.crt'),
	requestCert:		true,
	rejectUnauthorized: 	true,
};

function END_SUCCESS (res, http_status, msg)
{
	res.setHeader('content-type', 'application/json');
	res.status(http_status).end(msg + "\n");
}

function END_ERROR (res, http_status, msg)
{
	res.setHeader('content-type', 'application/json');
	res.status(http_status).end('{"error":"' + msg + '"}\n');
	res.connection.destroy();
}

function is_valid_email (email)
{
	if (typeof email !== 'string')
		return false;

	if (email.length < 5 || email.length > 64)
		return false;

	var num_ats	= 0;
	var num_dots	= 0;

	for (const chr of email)
	{
		if (
			(chr >= 'a' && chr <= 'z') ||
			(chr >= 'A' && chr <= 'Z') ||
			(chr >= '0' && chr <= '9')
		)
		{
			// ok;
		}
		else
		{
			switch (chr)
			{
				case '-':
				case '_':
					break;

				case '@':
					++num_ats;
					break;

				case '.':
					++num_dots;
					break;

				default:
					return false;
			}
		}
	}

	if (num_ats !== 1)
		return false;

	if (num_dots < 1)
		return false;

	return true;
}

function is_secure (req,res,expected_content_type)
{
	req.setTimeout(5000);

	res.header('x-xss-protection', '1; mode=block');
	res.header('x-frame-options', 'deny');
	res.header('x-content-type-options','nosniff');

	res.header('access-control-allow-origin', req.headers.origin ? req.headers.origin : '*');

	res.header(
		'access-control-allow-methods',
		'POST,GET'
	);

	res.header('connection','close');

	if (req.headers.referer)
	{
		// e.g https://www.iudx.org.in

		const referer_domain = String(
			req.headers.referer
				.split("/")[2]
				.split(":")[0]
		);

		// TODO maybe restrict to only few domains?

		if (! referer_domain.toLowerCase().endsWith('.iudx.org.in'))
			return "Invalid 'referer' field in the header";
	}

	if (expected_content_type)
	{
		const e = [expected_content_type, "text/plain"];

		if (e.indexOf(req.headers['content-type']) === -1) 
			return "content-type must be :" + expected_content_type;
	}

	if (! is_certificate_ok (req))
		return "Invalid certificate";

	return "OK";
}

function is_certificate_ok (req)
{
	// get full certificate chain
	const cert = req.socket.getPeerCertificate (true);

	if (! cert)
		return false;

	if ((! cert.subject) || (! cert.subject.emailAddress))
		return false;

	if (! is_string_safe(cert.subject.emailAddress))
		return false;

	if (! is_valid_email(cert.subject.emailAddress))
		return false;

	const issuer = cert.issuer;

	if ((! issuer) || (! issuer.emailAddress))
		return false;

	if (issuer.emailAddress.length < 5)
		return false;

	if (issuer.emailAddress.toLowerCase() === "ca@iudx.org.in")
	{
		if (has_iudx_certificate_been_revoked (req.socket,cert))
			return false;
	}
	else if (issuer.emailAddress.toLowerCase().startsWith("iudx.sub.ca@"))
	{
		const issued_to_domain	= cert.subject.emailAddress.split("@")[1];
		const issuer_domain	= issuer.emailAddress.split("@")[1];

		if (issuer_domain.toLowerCase() !== issued_to_domain.toLowerCase())
			return false;

		if (has_iudx_certificate_been_revoked (req.socket,cert))
		{
			log (	'red',
				"Revoked certificate used by: " +
				cert.subject.emailAddress
			);

			return false;
		}
	}

	return true;
}

function has_iudx_certificate_been_revoked (socket, cert)
{
	try
	{
		const now  = new Date();
		const diff = (now.getTime() - CRL_last_accessed.getTime())/1000.0;

		if (diff > CRL_SCAN_TIME)
		{
			const response = http_sync_request (
				'GET',
				'https://ca.iudx.org.in/crl'
			);

			try
			{
				CRL = JSON.parse(response.getBody());
				CRL_last_accessed = new Date();

				for (var i = 0; i < CRL.length; ++i)
				{
					CRL[i].issuer		= CRL[i].issuer.toLowerCase();	
					CRL[i].serial		= CRL[i].serial.toLowerCase().replace(/^0+/,"");
					CRL[i].fingerprint	= CRL[i].fingerprint.toLowerCase().replace(/:/g,"");
				}
			}
			catch(x)
			{
				return true; // something went wrong!
			}
		}

		const cert_fingerprint	= cert.fingerprint.replace(/:/g,'').toLowerCase();
		const cert_serial	= cert.serialNumber
						.toLowerCase()
						.replace(/^0+/,"");

		const cert_issuer	= cert.issuer.emailAddress.toLowerCase();

		for (const entry of CRL)
		{
			if (
				(entry.issuer		=== cert_issuer)	&&
				(entry.serial		=== cert_serial)	&&
				(entry.fingerprint	=== cert_fingerprint)
			)
			{
					return true;
			}
		}

		// If it was issued by a sub-CA then check the sub-CA's cert too
		// Assuming depth is <= 3. ca@iudx.org.in -> sub-CA -> user

		if (cert_issuer !== 'ca@iudx.org.in')
		{
			var ISSUERS = [];

			if (cert.issuerCertificate)
			{
				// both CA and sub-CA are the issuers
				ISSUERS.push(cert.issuerCertificate);

				if (cert.issuerCertificate.issuerCertificate)
					ISSUERS.push(cert.issuerCertificate.issuerCertificate);
			}
			else
			{
				/*
					This should not happen
				*/

				if (! socket.isSessionReused())
					return true;
			}

			for (const issuer of ISSUERS)
			{
				if (issuer.fingerprint && issuer.serialNumber)
				{
					const issuer_fingerprint	= issuer.fingerprint.replace(/:/g,'').toLowerCase();
					const issuer_serial		= issuer.serialNumber.toLowerCase();

					for (const entry of CRL)
					{
						if (entry.issuer === 'ca@iudx.org.in')
						{
							const entry_serial = entry.serial
										.toLowerCase()
										.replace(/^0+/,"");

							const entry_fingerprint	= entry.fingerprint
											.replace(/:/g,'')
											.toLowerCase();

							if (entry_serial === issuer_serial && entry_fingerprint == issuer_fingerprint)
								return true;
						}
					}
				}
				else
				{
					/*
						if fingerprint OR serial is undefined,
						then the session must have been reused
						by the client
					*/

					if (! socket.isSessionReused())
						return true;
				}
			}
		}

		return false;
	}
	catch (x)
	{
		log('red',"Exception in crl fetch ",x);
		return true; // by default !
	}
}

function is_string_safe (str,exceptions = "")
{
	if (! str)
		return false;

	if (typeof str !== 'string')
		return false;

	if (str.length === 0)
		return false;

	exceptions = exceptions + "-/@.";

	for (var i = 0; i < str.length; ++i)
	{
		const ch = str.charAt(i);

		if (
			(ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9')
		)
		{
			// ok
		}
		else
		{
			if (exceptions.indexOf(ch) === -1)
				return false;
		}
	}

	return true;
}

app.post('/auth/v1/token', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,"application/json")) !== "OK")
		return END_ERROR (res,400, error);

	if (req.headers['content-type'] === 'text/plain')
	{
		try
		{
			req.body = JSON.parse(req.body);
		}
		catch(e)
		{
			return END_ERROR (res,400, "body is not a valid JSON");
		}
	}

	const cert		= req.socket.getPeerCertificate();
	const consumer_id	= cert.subject.emailAddress.toLowerCase();

	var resource_server_token = {};

	var request_array 	= [];
	var resource_id_dict	= {};
	var response_array 	= [];

	if (req.body.request instanceof Array)
		request_array = req.body.request;
	else if (req.body.request instanceof Object)
		request_array = [req.body.request];
	else {
		return END_ERROR (res,400,"'request' field is not a valid JSON");
	}

	var cert_class = cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		cert_class = cert_class.split(":")[1];

		try {
			cert_class = parseInt(cert_class,10);
		}
		catch (x) {
			cert_class = 0;
		}
	}
	else {
		/* TODO OIDs of CCA/lisenced CAs issued certs
			1. CP 2.16.356.100.2
			2. CP Class 1 2.16.356.100.2.1
			3. CP Class 2 2.16.356.100.2.2
			4. CP Class 3 2.16.356.100.2.3
		*/

		cert_class = 2; // certificate issued by some other CA
	}

	if ( cert_class < 2) {

		return END_ERROR (res, 403,
			"A class-2 or above certificate is required" +
			" for this API"
		);
	}

	const token_rows = pg.querySync (
		'SELECT COUNT(*)/ (1 + EXTRACT(EPOCH FROM (NOW() - MIN(issued_at)))) '		+
		'AS rate '									+
		'FROM token '									+
		'WHERE id=$1::text '								+
		'AND DATE_TRUNC(\'day\',issued_at) = DATE_TRUNC(\'day\',NOW())',
			[consumer_id],
	);

	const tokens_rate_per_second = parseInt (token_rows[0].rate,10);

	if (tokens_rate_per_second > 3) { // tokens per second
		return END_ERROR (res, 429, "Too many requests"); // TODO report this!
	}

	const ip	= req.connection.remoteAddress;
	const geo	= geoip_lite.lookup(ip);
	const issuer	= cert.issuer;

	var context = {
		principal	: consumer_id,
		conditions	: {
			ip			: ip,
			time			: new Date(),

			'cert.class'		: cert_class,
			'cert.cn'		: cert.subject.CN 	|| "",
			'cert.o'		: cert.subject.O	|| "",
			'cert.ou'		: cert.subject.OU	|| "",
			'cert.c'		: cert.subject.C	|| "",
			'cert.st'		: cert.subject.ST	|| "",
			'cert.gn'		: cert.subject.GN	|| "",
			'cert.sn'		: cert.subject.SN	|| "",
			'cert.title'		: cert.subject.title	|| "",

			'cert.issuer.cn'	: issuer.CN		|| "",
			'cert.issuer.email'	: issuer.emailAddress	|| "",
			'cert.issuer.o'		: issuer.O		|| "",
			'cert.issuer.ou'	: issuer.OU		|| "",
			'cert.issuer.c'		: issuer.C		|| "",
			'cert.issuer.st'	: issuer.ST		|| "",

			country		 	: geo.country		|| "",
			region			: geo.region		|| "",
			timezone		: geo.timezone		|| "",
			city			: geo.city		|| "",
			latitude		: geo.ll[0]		||  0,
			longitude		: geo.ll[1]		||  0,
		}
	};

	var requested_token_time;	// as specified by the consumer
	var token_time = 31536000;	// to be finally sent along with token (max 1 year)

	if (req.body['token-time'])
	{
		try
		{
			requested_token_time = parseInt(req.body['token-time'],10);

			if (requested_token_time < 1)
				return END_ERROR (res, 403, "'token-time' field should be > 0");
		}
		catch (x)
		{
			return END_ERROR (res, 403, "Invalid 'token-time' field");
		}
	}

	const existing_token = req.body['existing-token'];

	var num_rules_passed = 0;
	var providers = {};

	for (const row of request_array)
	{
		var resource = row['resource-id'];

		if (! is_string_safe(resource,"* _")) // allow *, ,_ as a characters
			return END_ERROR (res, 400, "Invalid 'resource-id (contains unsafe chars)' :" + resource);

		if (typeof row.method === 'string')
			row.methods = [row.method];

		if (! row.methods)
			row.methods = ['*'];

		if ( ! (row.methods instanceof Array)) {

			return END_ERROR (res, 400,
				"Invalid 'methods' for resource id:" +
				resource
			);
		}

		if (row.api && typeof row.api === 'string')
			row.apis = [row.api];

		if (! row.apis)
			row.apis = ["/*"];

		if (row.provider)
		{
			if (typeof row.provider !== 'string')
			{
				return END_ERROR (res, 400,
					"Invalid 'provider': "+row.provider
				);
			}

			if (! is_valid_email(row.provider))
			{
				return END_ERROR (res, 400,
					"Invalid provider email: " +
						row.provider
				);
			}

			row.provider = row.provider.toLowerCase();

			const provider_email_domain	= row.provider.split("@")[1];

			const sha1_of_provider_email_id	= crypto.createHash('sha1')
								.update(row.provider)
								.digest('hex');

			resource =	provider_email_domain 		+
						"/"			+
					sha1_of_provider_email_id	+
						"/"			+
					resource;
		}

		if ((resource.match(/\//g) || []).length < 3)
		{
			return END_ERROR (res, 400,
				"Invalid 'resource-id' (it must have atleast 3 '/' chars): " +
				resource
			);
		}

		if (row.body)
		{
			if (! (row.body instanceof Object))
			{
				return END_ERROR (res, 400, "Invalid body for id :" + resource);
			}
		}

		const rid_split 		= resource.split("/");

		const provider_id_in_db		= rid_split[1] + '@' + rid_split[0];
		const resource_server		= rid_split[2];
		const resource_name		= rid_split.slice(3).join("/");

		providers		[provider_id_in_db]	= true;
		resource_server_token	[resource_server]	= true; // to be filled later

		const p_rows = pg.querySync (
			'SELECT policy_in_json FROM policy ' +
			'WHERE id = $1::text',
				[provider_id_in_db]
		);

		if (p_rows.length === 0)
			return END_ERROR (res, 400, "Invalid 'resource-id (no policy found)': " + resource);

		const policy_in_json = p_rows[0].policy_in_json;

		// full name of resource eg: bangalore.domain.com/streetlight-1
		context.resource	= resource_server + "/" + resource_name;
		context.action		= 'access';

		const g_rows = pg.querySync(
			'SELECT DISTINCT group_name FROM groups '	+
			'WHERE id = $1::text '				+
			'AND consumer = $2::text '			+
			'AND valid_till > NOW()',
				[provider_id_in_db, consumer_id]
		);

		var g = [];
		for (const grp of g_rows)
			g.push(grp.group_name);

		context.conditions.groups = g.join();

		// TODO : optimize, check if tokens_per_day is in rule
		const t_rows = pg.querySync (
			'SELECT COUNT(*) FROM token '		+
			'WHERE id=$1::text '			+
			'AND resource_ids @> $2 '		+
			'AND DATE_TRUNC(\'day\',issued_at) = DATE_TRUNC(\'day\',NOW())',
				[
					consumer_id,
					'{"' + resource + '":true}'
				],
		);

		context.conditions.tokens_per_day = parseInt (t_rows[0].count,10);

		// TODO optimize, see if body is in rule !
		var CTX;
		if (row.body)
		{
			// deep copy
			CTX = JSON.parse(JSON.stringify(context));

			for (const key in row.body)
				CTX.conditions["body." + key] = row.body[key];
		}
		else
			CTX = context;

		for (const api of row.apis)
		{
			if (typeof api !== 'string')
				return END_ERROR (res, 400, "Invalid 'api' :"+ api);

			CTX.conditions.api = api;

			for (const method of row.methods)
			{
				if (typeof method !== 'string')
					return END_ERROR (res, 400, "Invalid 'method' :"+ method);

				CTX.conditions.method = method;

				try
				{
					var token_time_in_policy; // as specified by the resource-owner in rules

					if (! (token_time_in_policy = evaluator.evaluate (policy_in_json,CTX)))
					{
						return END_ERROR (res, 403,
							"Unauthorized to access id :'"	+
								resource 		+
							"' for api :'"			+
								api			+
							"' and for method :'"		+
								method			+
							"'"
						);
					}

					token_time = Math.min(token_time, token_time_in_policy);
				}
				catch (x)
				{
					return END_ERROR (res, 403,
						"Unauthorized to access id :'"	+
							resource		+
						"' for api :'"			+
							api			+
						"' and for method :'"		+
							method			+
						"'"
					);
				}
			}
		}

		if (requested_token_time)
			token_time = Math.min (requested_token_time, token_time);

		var out = {
			"resource-id"	: resource,
			"methods"	: row.methods,
			"apis"		: row.apis,
		};

		if (row.body)
			out.body = row.body;

		response_array.push (out);

		resource_id_dict[resource] = true;

		num_rules_passed = num_rules_passed + 1;
	}

	var existing_row;
	if (num_rules_passed > 0 && num_rules_passed === request_array.length)
	{
		var token;

		if (existing_token)
		{
			if ((! existing_token.startsWith(OUR_NAME + "/")) || (! is_string_safe(existing_token)))
				return END_ERROR (res, 400, "Invalid 'existing-token' field");

			if ((existing_token.match(/\//g) || []).length !== 2)
				return END_ERROR (res, 400, "Invalid 'existing-token' field");

			const issued_by			= existing_token.split("/")[0];
			const issued_to			= existing_token.split("/")[1];
			const random_part_of_token	= existing_token.split("/")[2];

			if (
				(issued_by 			!== OUR_NAME)		||
				(issued_to			!== consumer_id)	||
				(random_part_of_token.length	!== TOKEN_LENGTH_HEX)
			) {
				return END_ERROR (res, 400, "Invalid existing-token");
			}

			const sha1_of_existing_token	= crypto.createHash('sha1')
								.update(random_part_of_token)
								.digest('hex');

			existing_row = pg.querySync (
				"SELECT EXTRACT(EPOCH FROM (expiry - NOW())) AS token_time,request,resource_ids,server_token "	+
					'FROM token WHERE '					+
					'id = $1::text AND '					+
					'token = $2::text AND '					+
					'revoked = false AND '					+
					'expiry > NOW()',
				[
					consumer_id,
					sha1_of_existing_token,
				]
			);

			if (existing_row.length === 0)
				return END_ERROR (res, 403, "Invalid existing-token");

			if (token_time < existing_row.token_time)
				token_time = existing_row.token_time;

			for (const k in existing_row[0].server_token)
			{
				resource_server_token[k] = existing_row[0].server_token[k];
			}

			token = random_part_of_token;
		}
		else
		{
			token = crypto.randomBytes(TOKEN_LENGTH).toString('hex');
		}

		var response = {

			/* Token format: issued-by / issued-to / token */

			"token"		: OUR_NAME + "/" + consumer_id + "/" + token,
			"token-type"	: "IUDX",
			"expires-in"	: token_time,
		};

		const num_resource_servers = Object.keys(resource_server_token).length;

		if (num_resource_servers > 1)
		{
			for (const ek in resource_server_token)
			{
				if (resource_server_token[ek] === true)
					resource_server_token[ek] = crypto.randomBytes(TOKEN_LENGTH).toString('hex');
			}

			response["server-token"] = resource_server_token;
		}

		const sha1_of_token	= crypto.createHash('sha1')
						.update(token)
						.digest('hex');

		if (existing_token)
		{
			// merge both existing values

			const old_request 	= existing_row[0].request;
			const new_request	= old_request.concat(request_array);

			const new_resource_ids_dict = Object.assign({},existing_row[0].resource_ids, resource_id_dict);

			pg.querySync (
				'UPDATE token SET ' 						+
					'request = $1,'						+
					'resource_ids = $2,'					+
					'server_token = $3,'					+
					"expiry = NOW() + interval '"+ token_time +" seconds' "	+
					'WHERE '						+
					'id = $4::text AND '					+
					'token = $5::text AND '					+
					'expiry > NOW()',
				[
					JSON.stringify(new_request),
					JSON.stringify(new_resource_ids_dict),
					JSON.stringify(resource_server_token),

					consumer_id,
					sha1_of_token,
				]
			);
		}
		else
		{
			const request = response_array;

			pg.querySync (
				'INSERT INTO token VALUES(' 				+
					'$1::text,'					+
					'$2::text,'					+
					"NOW() + interval '"+ token_time +" seconds',"	+
					'$3,'						+
					'$4::text,'					+
					'$5::text,'					+
					'NOW(),'					+
					'$6,'						+
					'$7,'						+
					'$8,'						+
					'$9,'						+
					'$10,'						+
					'$11'						+
				')',
				[
					consumer_id,
					sha1_of_token,
					JSON.stringify(request),
					cert.serialNumber,
					cert.fingerprint,
					JSON.stringify(resource_id_dict),
					'false',	// token not yet introspected
					'false',	// token not yet revoked
					cert_class,
					JSON.stringify(resource_server_token),
					JSON.stringify(providers)
				]
			);
		}

		return END_SUCCESS (res, 200, JSON.stringify(response));
	}
	else
	{
		return END_ERROR (res, 403, "Unauthorized!");
	}
});

app.post('/auth/v1/introspect', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK")
		return END_ERROR (res, 400, error);

	const cert = req.socket.getPeerCertificate();

	var cert_class = cert.subject['id-qt-unotice'];
	if (! cert_class)
	{
		return END_ERROR (res, 403,
			"A class-1 certificate required to call this API"
		);
	}

	cert_class = String(cert_class).split(":")[1];

	if ((! cert_class) || cert_class !== "1")
	{
		return END_ERROR (res, 403,
			"A class-1 certificate required to call this API"
		);
	}

	if (! req.body.token)
	{
		return END_ERROR (res, 400, "No 'token' found in the body");
	}

	const token = req.body.token;

	if ((! token.startsWith(OUR_NAME + "/")) || (! is_string_safe(token)))
		return END_ERROR (res, 400, "Invalid 'token' field");

	if ((token.match(/\//g) || []).length !== 2)
	{
		return END_ERROR (res, 400, "Invalid 'token' field");
	}

	const server_token = req.body['server-token'];

	if (server_token)
	{
		if (
			(server_token.length !== TOKEN_LENGTH_HEX) ||
			(! is_string_safe(server_token))
		) {
			return END_ERROR (res, 400, "Invalid 'server-token' field");
		}
	}

	const issued_by			= token.split("/")[0];
	const email_id_in_token		= token.split("/")[1];
	const random_part_of_token	= token.split("/")[2];

	if (
		(issued_by 			!== OUR_NAME)		||
		(random_part_of_token.length	!== TOKEN_LENGTH_HEX)
	) {
		return END_ERROR (res, 400, "Invalid token");
	}

	const sha1_of_token	= crypto.createHash('sha1')
					.update(random_part_of_token)
					.digest('hex');

	const ip 		= req.connection.remoteAddress;
	var ip_matched		= false;

	const resource_server_name_in_cert = cert.subject.CN;

	await dns.lookup(resource_server_name_in_cert, {all:true},
	async (error, ip_addresses) =>
	{
		if (error)
			return END_ERROR (res, 400, "Invalid hostname : "+resource_server_name_in_cert);

		for (const a of ip_addresses)
		{
			if (a.address === ip)
			{
				ip_matched = true;
				break;
			}
		}

		if (! ip_matched)
		{
			return END_ERROR (res, 403,
				"Your certificate hostname and " +
				"your IP does not match!"
			);
		}

		await pool.query (
				'SELECT expiry,request,cert_class,server_token,providers FROM token '	+
				'WHERE token = $1::text '			+
				'AND revoked = false '				+
				'AND expiry > NOW()',
					[sha1_of_token],
		async (error, results) =>
		{
			if (error)
				return END_ERROR (res, 500, "Internal error!");

			if (results.rows.length === 0)
				return END_ERROR (res, 400, "Invalid token 1");

			const expected_server_token = results.rows[0].server_token[resource_server_name_in_cert];
			const num_resource_servers = Object.keys(results.rows[0].server_token).length;

			if (num_resource_servers > 1)
			{
				// token is shared by many servers

				if (! server_token) // given by the user
					return END_ERROR (res, 403, "No 'server-token' field found in the body");

				if (! expected_server_token) // token doesn't belong to this server
					return END_ERROR (res, 400, "Invalid token 2");

				if (server_token !== expected_server_token)
					return END_ERROR (res, 403, "Invalid 'server-token' field in the body");
			}
			else
			{
				// token belongs to only 1 server

				if (expected_server_token !== true)
					return END_ERROR (res, 400, "Invalid token 3");
			}

			const request	= results.rows[0].request;
			const providers	= results.rows[0].providers;

			var request_for_resource_server = [];

			for (const r of request)
			{
				const a			= r["resource-id"].split("/");
				const provider 		= a[1] + "@" + a[0];
				const resource_server	= a[2];

				if (providers[provider]) // if provider exists in providers dictionary
				{
					if (resource_server === resource_server_name_in_cert)
						request_for_resource_server.push (r);
				}
			}

			if (request_for_resource_server.length === 0)
				return END_ERROR (res, 400, "Invalid token");

			const output = {
				'consumer'			: email_id_in_token,
				'expiry'			: results.rows[0].expiry,
				'request'			: request_for_resource_server,
				'consumer-certificate-class'	: results.rows[0].cert_class,
			};

			pg.querySync (
				"UPDATE token SET introspected = true WHERE " +
				"token = $1::text",
					[token]
			);

			return END_SUCCESS (res, 200, JSON.stringify(output));
		});
	});
});

app.post('/auth/v1/revoke', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,"application/json")) !== "OK")
		return END_ERROR (res, 400, error);

	const cert	= req.socket.getPeerCertificate();
	const id	= cert.subject.emailAddress.toLowerCase();

	var cert_class = cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		cert_class = cert_class.split(":")[1];
		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
		}
		catch (x)
		{
			cert_class = 2;
		}

		if (cert_class < 3)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required" +
				" for this API"
			);
		}
	}

	const tokens		= req.body.tokens;
	const token_hashes	= req.body['token-hashes'];

	if (tokens && token_hashes)
		return END_ERROR (res, 400, "Provide either 'tokens' or 'token-hashes', not both");

	if ( (! tokens) && (! token_hashes))
		return END_ERROR (res, 400, "Provide either 'tokens' or 'token-hashes'");

	if (tokens)
	{
		// user is a consumer

		if (! (tokens instanceof Array))
			return END_ERROR (res, 400, "Invalid 'tokens' field in body");

		for (const token of tokens)
		{
			if ((! is_string_safe(token)) || (! token.startsWith(OUR_NAME + "/")))
				return END_ERROR (res, 400, "Invalid token: "+token);

			if ((token.match(/\//g) || []).length !== 2)
				return END_ERROR (res, 400, "Invalid token: "+token);

			const issued_by			= token.split("/")[0];
			const issued_to			= token.split("/")[1];
			const random_part_of_token	= token.split("/")[2];

			if (
				(issued_by 			!== OUR_NAME)		||
				(issued_to			!== id)			||
				(random_part_of_token.length	!== TOKEN_LENGTH_HEX)
			) {
				return END_ERROR (res, 400, "Invalid token");
			}

			const sha1_of_token = crypto.createHash('sha1')
						.update(random_part_of_token)
						.digest('hex');

			await pool.query (

				'UPDATE token SET revoked = true WHERE id = $1::text ' 	+
				'AND token = $2::text '					+
				'AND expiry > NOW()',

				[id, sha1_of_token],

				async (error,results) =>
				{
					if (error)
						return END_ERROR (res, 500, "Some thing went wrong");

					if (results.rowCount === 0)
						return END_ERROR (res, 400, "Token not found");

					return END_SUCCESS (res, 200, '{"success":"token revoked"}');
				}
			);
		}
	}
	else
	{
		// user is a provider

		if (! (token_hashes instanceof Array))
			return END_ERROR (res, 400, "Invalid 'token-hashes' field in body");

		const sha1_id 		= crypto.createHash('sha1')
						.update(id)
						.digest('hex');

		const email_domain	= id.split("@")[1];

		const provider_id_in_db	= sha1_id + "@" + email_domain;

		for (const token_hash of token_hashes)
		{
			await pool.query (
				'UPDATE token '						+
				"SET provider->'" + sha1_id + "' = false "		+
				'WHERE token = $1::text '				+
				"AND providers->'"+ provider_id_in_db + "' = 'true' "	+
				'AND expiry > NOW()',
			[token_hash],

			async (error,results) =>
			{
				if (error)
					return END_ERROR (res, 500, "Some thing went wrong");

				if (results.rowCount === 0)
					return END_ERROR (res, 400, "Token hash not found : "+token_hash);

			});
		}

		return END_SUCCESS (res, 200, '{"succes":"token revoked"}');
	}
});

app.post('/auth/v1/acl/set', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,"application/json")) !== "OK")
		return END_ERROR (res, 400, error);

	const cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);
		}
	}

	if (! req.body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	const policy = req.body.policy;

	if (typeof policy !== 'string')
		return END_ERROR (res, 400, "Invalid policy");

	const provider_id	= cert.subject.emailAddress.toLowerCase();
	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash('sha1')
					.update(provider_id)
					.digest('hex');

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	const base64policy	= Buffer.from(policy).toString('base64');
	const rules		= policy.split(";");
	var policy_in_json;

	try {
		policy_in_json = rules.map(function (t) {
			return (parser.parse(t));
		});
	}
	catch (x) {
		const err = String(x).replace(/\n/g," ");
		return END_ERROR (res, 400, "Syntax error in policy: " + err);
	}

	await pool.query('SELECT 1 FROM policy WHERE id = $1::text',
		[provider_id_in_db], async (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Could not do SELECT on policy");

		var q; // query
		var p; // parameters

		if (results.rows.length > 0)
		{
			q = "UPDATE policy SET policy = $1::text," +
				"policy_in_json = $2 WHERE id = $3::text";
			p = [
				base64policy,
				JSON.stringify(policy_in_json),
				provider_id_in_db
			];
		}
		else
		{
			q = "INSERT INTO policy VALUES($1::text, $2::text, $3)";
			p = [
				provider_id_in_db,
				base64policy,
				JSON.stringify(policy_in_json)
			];
		}

		await pool.query (q, p, (int_error, _int_results) =>
		{
			if (int_error)
				return END_ERROR (res, 500, "Could not set policy");
			else
				return END_SUCCESS (res, 200, '{"success":"policy set"}');
		});
	});
});

app.post('/auth/v1/acl/append', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,"application/json")) !== "OK")
		return END_ERROR (res, 400, error);

	const cert	= req.socket.getPeerCertificate();

	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);
		}
	}

	if (! req.body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	const policy = req.body.policy;

	if (typeof policy !== 'string')
		return END_ERROR (res, 400, "Invalid policy");

	const provider_id	= cert.subject.emailAddress.toLowerCase();
	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash('sha1')
					.update(provider_id)
					.digest('hex');

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	const rules = policy.split(";");
	var policy_in_json;

	try {
		policy_in_json = rules.map(function (t) {
			return (parser.parse(t));
		});
	}
	catch (x) {
		const err = String(x).replace(/\n/g," ");
		return END_ERROR (res, 400, "Syntax error in policy :" + err);
	}

	await pool.query('SELECT policy FROM policy WHERE id = $1::text',
		[provider_id_in_db], async (error, results) =>
	{
		if (error)
			return END_ERROR (res,500, "Could not do SELECT on policy");

		var q; // query
		var p; // parameters

		if (results.rows.length > 0)
		{
			const old_policy	= Buffer.from(results.rows[0].policy, 'base64')
							.toString('ascii');

			const new_policy	= old_policy + ";" + policy;

			const base64policy	= Buffer.from(new_policy).toString('base64');

			const new_rules = new_policy.split(";");

			try {
				policy_in_json = new_rules.map(function (t) {
					return (parser.parse(t));
				});
			}
			catch (x) {
				const err = String(x).replace(/\n/g," ");
				return END_ERROR (res, 400, "Syntax error in policy: "+err);
			}

			q = "UPDATE policy SET policy = $1::text," +
				"policy_in_json = $2 WHERE id = $3::text";
			p = [
				base64policy,
				JSON.stringify(policy_in_json),
				provider_id_in_db
			];
		}
		else
		{
			const base64policy = Buffer.from(policy).toString('base64');

			q = "INSERT INTO policy VALUES($1::text, $2::text, $3)";
			p = [
				provider_id_in_db,
				base64policy,
				JSON.stringify(policy_in_json)
			];
		}

		await pool.query (q, p, (int_error, _int_results) =>
		{
			if (int_error)
				return END_ERROR (res, 500, "Could not set policy");
			else
				return END_SUCCESS (res, 200, '{"success":"policy appended"}');
		});
	});
});

app.get('/auth/v1/acl', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK")
		return END_ERROR (res, 400, error);

	const cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related"	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required " +
				"for calling policy related APIs"
			);
		}
	}

	const provider_id	= cert.subject.emailAddress.toLowerCase();
	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash('sha1')
					.update(provider_id)
					.digest('hex');

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query('SELECT policy FROM policy WHERE id = $1::text',
			[provider_id_in_db], (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Could not create the policy");

		if (results.rows.length === 0)
			return END_ERROR (res, 400, "No policies have been set yet!");

		const out = {
			'policy' : Buffer.from(results.rows[0].policy,'base64')
					.toString('ascii')
		};

		return END_SUCCESS (res, 200,
			JSON.stringify(out)
		);
	});
});

app.post('/auth/v1/audit/tokens', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK")
		return END_ERROR (res, 400, error);

	const cert	= req.socket.getPeerCertificate();
	const id	= cert.subject.emailAddress.toLowerCase();

	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);
		}
	}

	var hours;
	if (! (hours = req.body.hours))
		return END_ERROR (res, 400, "No 'hours' found in the body");

	try
	{
		hours = parseInt (hours,10);

		// 5 yrs max
		if (isNaN(hours) || hours < 0 || hours > 43800) {
			return END_ERROR (res, 400, "Invalid 'hours' field");
		}
	}
	catch (x) {
		return END_ERROR (res, 400, "Invalid 'hours' field");
	}

	var as_consumer = [];
	var as_provider = [];

	await pool.query (
		'SELECT issued_at,expiry,request,cert_serial,cert_fingerprint,introspected,revoked '	+
		'FROM token '										+
		'WHERE id = $1::text '									+
		'AND issued_at >= (NOW() + \'-'+ hours +' hours\')',

			[id], async (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!");

		for (var i = 0; i < results.rows.length; ++i)
		{
			const row = results.rows[i];

			as_consumer.push ({
				'token-issued-at'		: row.issued_at,
				'introspected'			: row.introspected === 't',
				'revoked'			: row.revoked === 't',
				'expiry'			: row.expiry,
				'certificate-serial-number'	: row.cert_serial,
				'certificate-fingerprint'	: row.cert_fingerprint,
				'request'			: row.request,
			});
		}

		const sha1_id 		= crypto.createHash('sha1')
						.update(id)
						.digest('hex');

		const email_domain	= id.split("@")[1];
		const provider_id_in_db	= sha1_id + "@" + email_domain;

		await pool.query (
			"SELECT id,token,issued_at,expiry,request,cert_serial,cert_fingerprint,"+
			"introspected,providers->'" + provider_id_in_db + "' AS is_revoked "	+
			'FROM token '								+
			"WHERE providers->'"+ provider_id_in_db + "' IS NOT NULL "		+
			'AND issued_at >= (NOW() + \'-'+ hours +' hours\')',

				[], (error, results) =>
			{

				if (error)
					return END_ERROR (res, 500, "Internal error!");

				for (var i = 0; i < results.rows.length; ++i)
				{
					const row = results.rows[i];

					as_provider.push ({
						'consumer'			: row.id,
						'token-hash'			: row.token,
						'token-issued-at'		: row.issued_at,
						'introspected'			: row.introspected === 't',
						'revoked'			: row.is_revoked === 't',
						'expiry'			: row.expiry,
						'certificate-serial-number'	: row.cert_serial,
						'certificate-fingerprint'	: row.cert_fingerprint,
						'request'			: row.request,
					});
				}

				const output = {
					'as-consumer'		: as_consumer,
					'as-resource-owner'	: as_provider,
				};

				res.setHeader('content-type', 'application/json');
				return END_SUCCESS (res, 200, JSON.stringify(output));
			}
		);
	});
});

app.post('/auth/v1/group/add', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK")
		return END_ERROR (res, 400, error);

	const cert		= req.socket.getPeerCertificate();
	const provider_id	= cert.subject.emailAddress.toLowerCase();

	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);
		}
	}

	if (! req.body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	const consumer_id = req.body.consumer.toLowerCase();

	if (! is_string_safe (consumer_id))
		return END_ERROR (res, 400, "Invalid 'consumer' field");

	if (! req.body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	const group_name = req.body.group.toLowerCase();

	if (! is_string_safe (group_name))
		return END_ERROR (res, 400, "Invalid 'group' field");

	var valid_till; // in hours
	if (! (valid_till = req.body["valid-till"]))
		return END_ERROR (res, 400, "No 'valid-till' found in the body");

	try {
		valid_till = parseInt(valid_till,10);

		// 1 year max
		if (isNaN(valid_till) || valid_till < 0 || valid_till > 8760) {
			return END_ERROR (res, 400, "Invalid 'valid-till' field");
		}
	}
	catch (x)
	{
		return END_ERROR (res, 400, "Invalid 'valid-till' field");
	}

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash('sha1')
					.update(provider_id)
					.digest('hex');

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query (
		"INSERT INTO groups VALUES ($1::text, $2::text, $3::text,"	+
		"NOW() + '"							+
			valid_till + " hours')",
				[provider_id_in_db, consumer_id, group_name],
	(error, _results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Could not add consumer to group");
		else
			return END_SUCCESS (res, 200, '{"success":"consumer added to the group"}');
	});
});

app.post('/auth/v1/group/list', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK")
		return END_ERROR (res, 400, error);

	const cert	= req.socket.getPeerCertificate();
	const provider_id	= cert.subject.emailAddress.toLowerCase();

	var cert_class	= cert.subject['id-qt-unotice'];
	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);
		}
	}

	var group_name = req.body.group;
	if (group_name)
	{
		group_name = group_name.toLowerCase();

		if (! is_string_safe (group_name))
			return END_ERROR (res, 400, "Invalid 'group' field");
	}

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash('sha1')
					.update(provider_id)
					.digest('hex');

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	var response = [];

	if (group_name)
	{
		await pool.query (
			"SELECT consumer, valid_till FROM groups "	+
			"WHERE id = $1::text "				+
			"AND group_name = $2::text "			+
			"AND valid_till > NOW()",
				[provider_id_in_db, group_name],
		(error, results) =>
		{
			if (error)
				return END_ERROR (res, 500, "Could not select group");

			for (const row of results.rows) {
				response.push (
					{
						"consumer"	: row.consumer,
						"valid-till"	: row.valid_till
					}
				);
			}

			res.setHeader('content-type', 'application/json');
			return END_SUCCESS (res, 200, JSON.stringify(response));
		});
	}
	else
	{
		await pool.query (
			"SELECT consumer, group_name, valid_till FROM groups "	+
			"WHERE id = $1::text "				+
			"AND valid_till > NOW()",
				[provider_id_in_db],
		(error, results) =>
		{
			if (error)
				return END_ERROR (res, 500, "Could not select group");

			for (const row of results.rows)
			{
				response.push (
					{
						"consumer"	: row.consumer,
						"group"		: row.group_name,
						"valid-till"	: row.valid_till
					}
				);
			}

			res.setHeader('content-type', 'application/json');
			return END_SUCCESS (res, 200, JSON.stringify(response));
		});
	}
});

app.post('/auth/v1/group/delete', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK")
		return END_ERROR (res, 400, error);

	const cert		= req.socket.getPeerCertificate();
	const provider_id	= cert.subject.emailAddress.toLowerCase();

	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				return END_ERROR (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);
			}
		}
		catch(x)
		{
			return END_ERROR (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);
		}
	}

	if (! req.body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	const consumer_id = req.body.consumer.toLowerCase();

	if (! is_string_safe (consumer_id))
		return END_ERROR (res, 400, "Invalid 'consumer' field");

	if (! req.body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	const group_name = req.body.group.toLowerCase();

	if (! is_string_safe (group_name))
		return END_ERROR (res, 400, "Invalid 'group' field");

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash('sha1')
					.update(provider_id)
					.digest('hex');

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	var query =
		"DELETE FROM groups "		+
		"WHERE id = $1::text "		+
		"AND group_name = $2::text "	+
		"AND valid_till > NOW()";

	const params = [provider_id_in_db, group_name];

	if (consumer_id !== '*')
	{
		query += " AND consumer = $3::text ";
		params.push(consumer_id);
	}

	await pool.query (query, params, (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Could not delete from group");

		if (results.rowCount === 0)
		{
			if (consumer_id === '*')
				return END_ERROR (res, 400, "Empty group");
			else
				return END_ERROR (res, 400, "Consumer not in the group");
		}
		else
		{
			return END_SUCCESS (res, 200, '{"success":"' + results.rowCount+ ' consumer(s) deleted from the group"}');
		}
	});
});

app.get("/auth/v1/[^.]*/help", function (req, res) {
	const pathname	= url.parse(req.url).pathname;
	const api	= pathname.split("/auth/v1/")[1].split("/help")[0];

	if (api)
	{
		res.setHeader('content-type', 'text/plain');
		res.sendFile(__dirname + '/public/help/' + api + ".txt");
	}
	else
	{
		res.status(404).end("No such API");
		res.connection.destroy();
	}
});

app.post("/auth/v1/[^.]*/help", function (req, res) {
	const pathname	= url.parse(req.url).pathname;
	const api	= pathname.split("/auth/v1/")[1].split("/help")[0];

	if (api)
	{
		res.setHeader('content-type', 'text/plain');
		res.sendFile(__dirname + '/public/help/' + api + ".txt");
	}
	else
	{
		return END_ERROR (res, 404, "No such API");
	}
});

app.get('/*', function (req, res) {
	const pathname = url.parse(req.url).pathname;
	console.log("=>>> GET  not found for :",pathname);
	res.status(405).end("No such API");
	return;
});

app.post('/*', function (req, res) {
	const pathname = url.parse(req.url).pathname;
	console.log("=>>> POST not found for :",pathname);
	res.status(405).end("No such API");
	return;
});

app.on('error', function(e) {
	console.error(e);
});

//////////////////////// RUN /////////////////////////////////

var num_cpus = os.cpus().length;

if (num_cpus < 4)
	num_cpus = 2;

if (! is_openbsd)
{
	// ======================== START preload code for chroot ==============

	var _tmp = ["x can x x"].map(function (t) {
		return (parser.parse(t));
	});

	evaluator.evaluate(_tmp, {});

	dns.lookup("www.google.com", {all:true}, (_e,_a) => {});

	_tmp = http_sync_request('GET', 'https://ca.iudx.org.in/crl');

	// ======================== END preload code for chroot   ==============
}

function drop_privilege ()
{
	if (! do_drop_privilege)
		return;

	if (is_openbsd)
	{
		if (EUID === 0)
		{
			process.setgid('nogroup');
			process.setuid('nobody');
		}

		unveil('/usr/bin/nc',			'rx');
		unveil('/usr/lib',			'r' );
		unveil('/usr/libexec/ld.so',		'r' );
		unveil(__dirname + '/node_modules',	'r' );
		unveil(__dirname + '/node-aperture',	'r' );
		unveil(__dirname + '/public',		'r' );

		unveil();
	}
	else
	{
		if (EUID === 0)
		{
			chroot('/var/iudx-chroot','nobody');
			process.chdir ('/');

			process.setgid('nogroup');
			process.setuid('nobody');
		}
	}

	if (is_openbsd)
		pledge.init (WORKER_PLEDGE);
}

if (cluster.isMaster)
{
	if (is_openbsd)
	{
		pledge.init (WORKER_PLEDGE + " unveil sendfd");

	}

	log('green',`Master ${process.pid} is running`);

	for (var i = 0; i < num_cpus; i++) {
		cluster.fork();
	}

	cluster.on('exit', (worker, _code, _signal) => {
		log('red',`Worker ${worker.process.pid} died, restarting it`);
		cluster.fork();
	});
}
else
{
	https.createServer (https_options,app).listen(443,'0.0.0.0');
	drop_privilege();
	log('green',`Worker ${process.pid} started `);
}

// forget password
db_password = "";

//////////////////////////////////////////////////////////////
