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

const WORKER_PLEDGE = "stdio tty prot_exec inet dns recvfd rpath proc exec";

var pledge;
var unveil;

if (os.type() === 'OpenBSD') {
	pledge	= require("node-pledge");
	unveil	= require("openbsd-unveil");
}

const OUR_NAME		= 'auth.iudx.org.in';
const URL_ENCODED	= 'application/x-www-form-urlencoded';
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

function log(color, msg) {
	logger.color(color).log(new Date() + " | " + msg);
}

var do_drop_privilege = true;
const argv = process.argv.slice(2);

if (argv.length < 1) {
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

var postgres_password = fs.readFileSync ('postgres.password','ascii').trim();

const pool = new Pool ({
	host		: '127.0.0.1',
	port		: 5432,
	user		: 'postgres',
	database	: 'postgres',
	password	: postgres_password,
});

pool.connect();

pg.connectSync (
	'postgresql://postgres:'+ postgres_password+ '@127.0.0.1:5432/postgres',
		function(err) {
			if(err) throw err;
		}
);

var app = express();

app.use (cors());

app.use(bodyParser.json(
));

app.use(bodyParser.urlencoded({
	extended	: true,
	parameterLimit	: 1,
}));

app.disable('x-powered-by');

app.get('/doc', function (req, res) {
	res.sendFile(__dirname + '/public/hyperspace/index.html');
});

app.use("/assets", express.static(__dirname + "/public/hyperspace/assets"));

var apertureOpts = {

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

	groups				: 'string',	// csv actually

	country				: 'string',
	region				: 'string',
	timezone			: 'string',
	city				: 'string',
	latitude			: 'number',
	longitude			: 'number',
    }
};

var parser	= aperture.createParser		(apertureOpts);
var evaluator	= aperture.createEvaluator	(apertureOpts);

const https_options = {
	key:			fs.readFileSync('key.pem'),
	cert:			fs.readFileSync('server.pem'),
	ca:			fs.readFileSync('ca.iudx.org.in.crt'),
	requestCert:		true,
	rejectUnauthorized: 	true,
};

function END (res, http_status, msg)
{
	res.status(http_status).end(msg + "\n");
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

	for (var chr of email)
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

	res.header('access-control-allow-headers','*');
	res.header('access-control-allow-origin', '*');

	res.header(
		'access-control-allow-methods',
		'POST, GET, OPTIONS'
	);
	res.header(
		'strict-transport-security',
		'max-age=31536000; includeSubDomains'
	);

	res.header('connection','close');

	if (req.headers.referer)
	{
		// e.g https://www.iudx.org.in

		var referer_domain = String(
			req.headers.referer
				.split("/")[2]
				.split(":")[0]
		);

		if (! referer_domain.toLowerCase().endsWith('.iudx.org.in'))
			return "Invalid 'referer' field in the header";
	}

	if (expected_content_type)
	{
		if (req.headers['content-type'] !== expected_content_type)
			return "content-type must be :" + expected_content_type;
	}

	if (! is_certificate_ok (req))
		return "Invalid certificate";

	return "OK";
}

function is_certificate_ok (req)
{
	// get full certificate chain
	var cert = req.socket.getPeerCertificate (true);

	if (! cert)
		return false;

	if ((! cert.subject) || (! cert.subject.emailAddress))
		return false;

	if (! is_string_safe(cert.subject.emailAddress))
		return false; 

	if (! is_valid_email(cert.subject.emailAddress))
		return false; 

	var issuer = cert.issuer;

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
		var issued_to_domain	= cert.subject.emailAddress.split("@")[1];
		var issuer_domain	= issuer.emailAddress.split("@")[1];

		if (issuer_domain.toLowerCase() !== issued_to_domain.toLowerCase())
			return false;

		if (has_iudx_certificate_been_revoked (req.socket,cert)) {
			log('red',"Revoked certificate used by: "+ cert.subject.emailAddress);
			return false;
		}
	}

	return true;
}

function has_iudx_certificate_been_revoked (socket, cert)
{
	try
	{
		var now	 = new Date();

		var diff = (now.getTime() - CRL_last_accessed.getTime())/1000.0;

		if (diff > CRL_SCAN_TIME)
		{
			var response = http_sync_request (
				'GET',
				'https://ca.iudx.org.in/crl'
			);

			try
			{
				CRL = JSON.parse(response.getBody());
				CRL_last_accessed = new Date(); 
			}
			catch(x)
			{
				return true; // something went wrong!
			}
		}

		var fingerprint	= cert.fingerprint.replace(/:/g,'').toLowerCase();

		var serial	= cert.serialNumber
					.toLowerCase()
					.replace(/^0+/,"");

		var issuer = cert.issuer.emailAddress.toLowerCase();
		var entry; // in CRL

		for (entry of CRL)
		{
			if (entry.issuer === issuer) 
			{
				entry.serial = entry.serial.toLowerCase();
				entry.serial = entry.serial.replace(/^0+/,"");

				if (entry.serial === serial)
					return true;
			}
		}

		// If it was issued by a sub-CA then check the sub-CA's cert too
		// Assuming depth is <= 3. ca@iudx.org.in -> sub-CA -> user

		if (issuer !== 'ca@iudx.org.in')
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
				if (! socket.isSessionReused())
					return true;
			}

			for (issuer of ISSUERS)
			{ 
				if (issuer.fingerprint && issuer.serialNumber)
				{
					fingerprint	= issuer.fingerprint.replace(/:/g,'').toLowerCase();
					serial		= issuer.serialNumber.toLowerCase();

					for (entry of CRL)
					{
						if (entry.issuer === 'ca@iudx.org.in') 
						{
							entry.serial = entry.serial.toLowerCase();
							entry.serial = entry.serial.replace(/^0+/,"");

							if (entry.serial === serial) 
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

function is_string_safe (str)
{
	if (! str)
		return false;

	if (typeof str !== 'string')
		return false;

	if (str.length === 0)
		return false;

	for (var i = 0; i < str.length; ++i)
	{
		var ch = str.charAt(i);

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
			switch (ch)
			{
				case '-': // For email, APIs, tokens
				case '/': // For APIs and tokens
				case '@': // For email
				case '.': // For email and APIs
					break;

				default:
					return false;
			}
		}
	}

	return true;
}

app.post('/auth/v1/token', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,'application/json')) !== "OK") {
		END (res,400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var consumer_id	= cert.subject.emailAddress.toLowerCase();

	var resource_server_token = {};

	var request_array 	= [];
	var resource_id_dict	= {};
	var response_array 	= [];

	if (req.body instanceof Array)
		request_array = req.body;
	else if (req.body instanceof Object)
		request_array = [req.body];
	else {
		END (res,400,"Body is not a valid JSON");
		return;
	}

	var cert_class = cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		cert_class = cert_class.split(":")[1];

		if ( (! cert_class) || cert_class === "1") {

			END (res, 403,
				"A class-2 or above certificate is required" +
				" for this API"
			);

			return;
		}

		try {
			cert_class = parseInt(cert_class,10);
		}
		catch (x) {
			cert_class = 2;
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

	var token_rows = pg.querySync (
		'SELECT COUNT(*)/ (1 + EXTRACT(EPOCH FROM (NOW() - MAX(issued_at)))) AS rate '	+
		'FROM token '									+ 
		'WHERE id=$1::text '								+
		'AND DATE_TRUNC(\'day\',issued_at) = DATE_TRUNC(\'day\',NOW())',
			[consumer_id],
	);

	var tokens_rate_per_second = parseInt (token_rows[0].rate,10);

	if (tokens_rate_per_second > 3) { // 3 tokens per second 

		END (res, 429, "Too many requests"); // TODO report this!
		return;

	}

	var ip		= req.connection.remoteAddress;
	var geo		= geoip_lite.lookup(ip);
	var issuer	= cert.issuer;

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

	var token_time;
	var requested_token_time;		// as specified by the subscriber
	var token_time_in_policy;		// as specified by the provider

	if (req.headers['token-time'])
	{
		try
		{
			requested_token_time = parseInt(req.headers['token-time'],10);
		}
		catch (x)
		{
			END (res, 403, "Invalid 'token-time' field");
		}
	}

	var num_rules_passed = 0;

	for (var row of request_array)
	{
		var resource = row['resource-id'];

		if (! is_string_safe(resource)) {
			END (res, 400, "Invalid 'resource-id (contains unsafe chars)' :" + resource);
			return;
		}

		if (typeof row.method === 'string') {
			row.methods = [row.method];
		}

		if (! row.methods)
			row.methods = ['*'];

		if ( ! (row.methods instanceof Array)) {

			END (res, 400,
				"Invalid 'methods' for resource id:" +
				resource
			);

			return;
		}

		if (row.api && typeof row.api === 'string')
			row.apis = [row.api];

		if (! row.apis)
			row.apis = ["/*"];

		if (row.provider)
		{
			if (typeof row.provider !== 'string') {

				END (res, 400,
					"Invalid 'provider': "+row.provider
				);

				return;
			}

			if (! is_valid_email(row.provider))
			{
				END (res, 400,
					"Invalid provider email: " +
						row.provider
				);

				return;
			}

			row.provider = row.provider.toLowerCase();

			var provider_email_domain	= row.provider.split("@")[1];

			var provider_email_id_hash	= crypto.createHash('sha1')
							.update(row.provider);

			var sha1_of_provider_email_id	= provider_email_id_hash
							.digest('hex');

			resource =	provider_email_domain 		+
						"/"			+
					sha1_of_provider_email_id	+
						"/"			+
					resource;
		}

		if ((resource.match(/\//g) || []).length < 3) {

			END (res, 400, 
				"Invalid 'resource-id' (it must have atleast 3 '/' chars): " +
				resource
			);

			return;
		}

		if (row.body)
		{
			if (! (row.body instanceof Object)) {

				END (res, 400, "Invalid body for id :" + resource);

				return;
			}
		}

		var rid_split 			= resource.split("/");

		var provider_id_in_db		= rid_split[1] + '@' + rid_split[0];
		var resource_server		= rid_split[2];
		var resource_name		= rid_split.slice(3).join("/");

		resource_server_token [resource_server] = true; // to be filled later

		var p_rows = pg.querySync (
			'SELECT policy_in_json FROM policy ' +
			'WHERE id = $1::text',
				[provider_id_in_db]
		);

		if (p_rows.length === 0) {
			END (res, 400, "Invalid 'resource-id (no policy found)': " + resource);
			return;
		}

		var policy_in_json = p_rows[0].policy_in_json;

		// full name of resource eg: bangalore.domain.com/streetlight-1
		context.resource	= resource_server + "/" + resource_name;
		context.action		= 'access';

		var g_rows = pg.querySync(
			'SELECT DISTINCT group_name FROM groups '	+
			'WHERE id = $1::text '				+
			'AND consumer = $2::text '			+
			'AND valid_till > NOW()',
				[provider_id_in_db, consumer_id]
		);

		var g = [];
		for (var gr of g_rows)
			g.push(gr.group_name);

		context.conditions.groups = g.join();

		// TODO : optimize, check if tokens_per_day is in rule
		token_rows = pg.querySync (
			'SELECT COUNT(*) FROM token '		+
			'WHERE id=$1::text '			+
			'AND resource_ids @> $2 '		+
			'AND DATE_TRUNC(\'day\',issued_at) = DATE_TRUNC(\'day\',NOW())',
				[
					consumer_id,
					'{\"' + resource + '\":true}'
				],
		);

		context.conditions.tokens_per_day = parseInt (token_rows[0].count,10); 

		// TODO optimize, see if body is in rule !
		var CTX;
		if (row.body)
		{
			// deep copy
			CTX = JSON.parse(JSON.stringify(context));

			var key;

			for (key in row.body)
				CTX.conditions["body." + key] = row.body[key];
		}
		else
			CTX = context;

		for (var api of row.apis)
		{
			if (typeof api !== 'string') {
				END (res, 400, "Invalid 'api' :"+ api);
				return;
			}

			CTX.conditions.api = api;

			for (var method of row.methods)
			{
				if (typeof method !== 'string') {
					END (res, 400, "Invalid 'method' :"+ method);
					return;
				}

				CTX.conditions.method = method;

				try {
					if (! (token_time_in_policy = evaluator.evaluate (policy_in_json,CTX))) {

						END (res, 403,
							"Unauthorized to access id :'"	+
								resource 		+
							"' for api :'"			+
								api			+
							"' and for method :'"		+
								method			+
							"'"
						);

						return;
					}

					if (token_time)
						token_time = Math.min(token_time, token_time_in_policy);
					else
						token_time = token_time_in_policy;
				}
				catch (x) {

					END (res, 403,
						"Unauthorized to access id :'"	+
							resource		+
						"' for api :'"			+
							api			+
						"' and for method :'"		+
							method			+
						"'"
					);

					return;
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

	if (num_rules_passed > 0 && num_rules_passed === request_array.length)
	{
		var token = crypto.randomBytes(16).toString('hex'); 

		for (var k in resource_server_token)
		{
			resource_server_token[k] = crypto.randomBytes(16).toString('hex'); 
		}

		var response = {

			/* Token format: issued-by / issued-to / token */

			"token"		: OUR_NAME + "/" + consumer_id + "/" + token,
			"token-type"	: "IUDX",
			"expires-in"	: token_time,
			"server-token"	: resource_server_token
		};

		var token_hash		= crypto.createHash('sha1').update(token);
		var sha1_of_token	= token_hash.digest('hex');

		var request_string_base64 = Buffer.from (
			JSON.stringify(response_array)
		).toString('base64');

		pg.querySync (
			'INSERT INTO token VALUES(' 				+
				'$1::text,'					+
				'$2::text,'					+
				'NOW() + interval \''+ token_time +' seconds\','+
				'$3::text,'					+
				'$4::text,'					+
				'$5::text,'					+
				'NOW(),'					+
				'$6,'						+
				'$7,'						+
				'$8,'						+
				'$9,'						+
				'$10'						+
			')',
			[
				consumer_id,
				sha1_of_token,
				request_string_base64,
				cert.serialNumber,
				cert.fingerprint,
				JSON.stringify(resource_id_dict),
				'false',	// token not yet introspected
				'false',	// token not yet revoked 
				cert_class,
				JSON.stringify(resource_server_token),
			]
		);

		res.setHeader('content-type', 'application/json');
		END (res, 200, JSON.stringify(response));
		return;
	}
	else
	{
		END (res, 403, "Unauthorized!");
		return;
	}
});

app.post('/auth/v1/introspect', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert = req.socket.getPeerCertificate();

	var cert_class = cert.subject['id-qt-unotice'];
	if (! cert_class) {

		END (res, 403,
			"A class-1 certificate required to call this API"
		);

		return;
	}

	cert_class = String(cert_class).split(":")[1];

	if ((! cert_class) || cert_class !== "1") {

		END (res, 403,
			"A class-1 certificate required to call this API"
		);

		return;
	}

	var token;
	if (! (token = req.headers.token)) {
		END (res, 400, "No 'token' found in the header");
		return;
	}

	if ((! is_string_safe(token)) || (! token.startsWith(OUR_NAME + "/"))) {
		END (res, 400, "Invalid 'token' field");
		return;
	}

	if ((token.match(/\//g) || []).length !== 2) {
		END (res, 400, "Invalid 'token' field");
		return;
	}

	var server_token;
	if (! (server_token = req.headers['server-token'])) {
		END (res, 400, "No 'server-token' found in the header");
		return;
	}

	if (! is_string_safe(server_token)) {
		END (res, 400, "Invalid 'server-token' field");
		return;
	}

	var issued_by		= token.split("/")[0];
	var email_id_in_token	= token.split("/")[1];
	var random_token	= token.split("/")[2];

	if (issued_by !== OUR_NAME) {
		END (res, 400, "Invalid token");
		return;
	}

	var token_hash		= crypto.createHash('sha1').update(random_token);
	var sha1_of_token	= token_hash.digest('hex');

	var ip 		= req.connection.remoteAddress;
	var ip_matched	= false;

	var resource_server_name_in_cert = cert.subject.CN;

	await dns.lookup(resource_server_name_in_cert, {all:true},
	async (error, addresses) =>
	{
		if (error) {
			END (res, 400, "Invalid hostname :"+error);
			return;
		}

		for (var a of addresses)
		{
			if (a.address === ip)
			{
				ip_matched = true;
				break;
			}
		}

		if (! ip_matched)
		{
			END (res, 403,
				"Your certificate hostname and " +
				"your IP does not match!"
			);

			return;
		}

		await pool.query (
				'SELECT expiry,request,cert_class,server_token FROM token '	+
				'WHERE token = $1::text '			+
				'AND revoked = false '				+
				'AND expiry > NOW()',
					[sha1_of_token],
		async (error, results) =>
		{
			if (error) {
				END (res, 500, "Internal error!");
				return;
			}

			if (results.rows.length === 0) {
				END (res, 400, "Invalid token");
				return;
			}

			if (server_token !== results.rows[0].server_token[resource_server_name_in_cert])
			{
				END (res, 500, "Invalid 'server-token'");
				return;
			}
				
			var request;
			var request_for_resource_server = [];

			try {
				request = JSON.parse (
					Buffer.from (results.rows[0].request,'base64')
						.toString('ascii')
				);
			}
			catch (x) {
				END (res, 500, "Invalid request in DB");
				return;
			}

			for (var r of request)
			{
				var resource_server = r["resource-id"].split("/")[2];

				if (resource_server === resource_server_name_in_cert)
					request_for_resource_server.push (r);
			}

			if (request_for_resource_server.length === 0) {
				END (res, 400, "Invalid token");
				return;
			}

			var output = {
				'active'			: true,
				'username'			: email_id_in_token,
				'expiry'			: results.rows[0].expiry,
				'request'			: request_for_resource_server,
				'user-certificate-class'	: results.rows[0].cert_class,
			};

			pg.querySync (
				"UPDATE token SET introspected = true WHERE " +
				"token = $1::text",
					[token]
			);

			res.setHeader('content-type', 'application/json');
			END (res, 200, JSON.stringify(output));
			return;
		});
	});
});

app.post('/auth/v1/revoke', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var consumer_id	= cert.subject.emailAddress.toLowerCase();

	var cert_class = cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		cert_class = cert_class.split(":")[1];

		if (cert_class === "1") {

			END (res, 403,
				"A class-2 or above certificate is required" +
				" for this API"
			);

			return;
		}
	}

	var token;
	if (! (token = req.headers.token)) {
		END (res, 400, "No 'token' found in the header");
		return;
	}

	if ((! is_string_safe(token)) || (! token.startsWith(OUR_NAME + "/"))) {
		END (res, 400, "Invalid token");
		return;
	}

	if ((token.match(/\//g) || []).length !== 2) {
		END (res, 400, "Invalid token");
		return;
	}

	var issued_by		= token.split("/")[0];
	var issued_to		= token.split("/")[1];
	var random_token	= token.split("/")[2];

	if (issued_by !== OUR_NAME) {
		END (res, 400, "Invalid token");
		return;
	}

	if (issued_to !== consumer_id) {
		END (res, 400, "Unauthorized!");
		return;
	}

	var token_hash		= crypto.createHash('sha1').update(random_token);
	var sha1_of_token	= token_hash.digest('hex');

	await pool.query (
			'UPDATE token SET revoked = true WHERE id = $1::text ' 	+
			'AND token = $2::text '					+
			'AND cert_serial = $3::text '				+
			'AND cert_fingerprint = $4::text',

		[consumer_id,sha1_of_token,cert.serialNumber,cert.fingerprint],

		async (error,results) =>
		{
			if (error) {
				END (res, 500, "Some thing went wrong");
				return;
			}

			if (results.rowCount === 0) {
				END (res, 400, "Token not found");
				return;
			}

			END (res, 200, "token revoked");
			return;
		}
	);
});

app.post('/auth/v1/acl', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,URL_ENCODED)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);

			return;
		}
	}

	var policy;
	if (! (policy = req.body.policy)) {
		END (res, 400, "No 'policy' found in request");
		return;
	}

	if (typeof policy !== 'string') {
		END (res, 400, "Invalid policy");
		return;
	}

	var provider_id		= cert.subject.emailAddress.toLowerCase();
	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	var base64policy = Buffer.from(policy).toString('base64');
	var rules = policy.split(";");
	var policy_in_json;

	try {
		policy_in_json = rules.map(function (t) {
			return (parser.parse(t));
		});
	}
	catch (x) {
		END (res, 400, "Syntax error in policy: " + x);
		return;
	}

	await pool.query('SELECT 1 FROM policy WHERE id = $1::text',
		[provider_id_in_db], async (error, results) =>
	{
		if (error) {
			END (res, 500, "Could not do SELECT on policy");
			return;
		}

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

		await pool.query (q, p, (int_error, int_results) =>
		{
			if (int_error)
			{
				END (res, 500, "Could not set policy");
				return;
			}

			END (res, 200, '');
			return;
		});
	});
});

app.post('/auth/v1/append-acl', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,URL_ENCODED)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);

			return;
		}
	}

	var policy;
	if (! (policy = req.body.policy)) {
		END (res, 400, "No 'policy' found in request");
		return;
	}

	if (typeof policy !== 'string') {
		END (res, 400, "Invalid policy"); 
		return;
	}

	var provider_id		= cert.subject.emailAddress.toLowerCase();
	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	var rules = policy.split(";");
	var policy_in_json;

	try {
		policy_in_json = rules.map(function (t) {
			return (parser.parse(t));
		});
	}
	catch (x) {
		END (res, 400, "Syntax error in policy :" + x);
		return;
	}

	await pool.query('SELECT policy FROM policy WHERE id = $1::text',
		[provider_id_in_db], async (error, results) =>
	{
		if (error) {
			END (res,500, "Could not do SELECT on policy");
			return;
		}

		var q; // query
		var p; // parameters

		var old_policy;
		var base64policy;

		if (results.rows.length > 0)
		{
			old_policy	= Buffer.from(results.rows[0].policy, 'base64')
						.toString('ascii');

			var new_policy	= old_policy + ";" + policy;

			base64policy	= Buffer.from(new_policy).toString('base64');

			rules = new_policy.split(";");

			try {
				policy_in_json = rules.map(function (t) {
					return (parser.parse(t));
				});
			}
			catch (x) {
				END (res, 400, "Syntax error in policy: "+x);
				return;
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
			base64policy = Buffer.from(policy).toString('base64');

			q = "INSERT INTO policy VALUES($1::text, $2::text, $3)";
			p = [
				provider_id_in_db,
				base64policy,
				JSON.stringify(policy_in_json)
			];
		}

		await pool.query (q, p, (int_error, int_results) =>
		{
			if (int_error)
			{
				END (res, 500, "Could not set policy");
				return;
			}

			END (res, 200, "");
			return;
		});
	});
});

app.get('/auth/v1/acl', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related"	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required " +
				"for calling policy related APIs"
			);

			return;
		}
	}

	var provider_id		= cert.subject.emailAddress.toLowerCase();
	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query('SELECT policy FROM policy WHERE id = $1::text',
			[provider_id_in_db], (error, results) =>
	{
		if (error) {
			END (res, 500, "Could not create the policy");
			return;
		}

		if (results.rows.length === 0) {
			END (res, 400, "No policies have been set yet!");
			return;
		}

		END (res, 200,
			Buffer.from(results.rows[0].policy,'base64')
				.toString('ascii')
		);

		return;
	});
});

app.post('/auth/v1/audit/tokens', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var consumer_id	= cert.subject.emailAddress.toLowerCase();

	var hours;
	if (! (hours = req.headers.hours)) {
		END (res, 400, "No 'hours' found in the headers");
		return;
	}

	try
	{
		hours = parseInt (hours,10);

		// 5 yrs max
		if (isNaN(hours) || hours < 0 || hours > 43800) {
			END (res, 400, "Invalid 'hours' field");
			return;
		}
	}
	catch (x) {
		END (res, 400, "Invalid 'hours' field");
		return;
	}

	await pool.query (
		'SELECT issued_at,expiry,request,cert_serial,cert_fingerprint,introspected '	+
		'FROM token '									+
		'WHERE id = $1::text '								+
		'AND issued_at >= (NOW() + \'-'+ hours +' hours\')',

			[consumer_id], (error, results) =>
	{
		if (error) {
			END (res, 500, "Internal error!");
			return;
		}

		var output = [];

		for (var i = 0; i < results.rows.length; ++i)
		{
			var request_in_json;
			try {
				request_in_json = JSON.parse (
					Buffer.from (
						results.rows[i].request,'base64'
					).toString('ascii')
				);
			}
			catch (x) {
				END (res, 500, "Invalid request in DB");
				return;
			}

			var row = results.rows[i];

			output.push ({
				'token-issued-at'		: row.issued_at,
				'introspected'			: row.introspected === 't',
				'expiry'			: row.expiry,
				'certificate-serial-number'	: row.cert_serial,
				'certificate-fingerprint'	: row.cert_fingerprint,
				'request'			: request_in_json,
			});
		}

		res.setHeader('content-type', 'application/json');
		END (res, 200, JSON.stringify(output));
		return;
	});
});

app.post('/auth/v1/group/add-consumer', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];
	var provider_id	= cert.subject.emailAddress.toLowerCase();

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);

			return;
		}
	}

	var consumer_id;
	if (! (consumer_id = req.headers.consumer)) {
		END (res, 400, "No 'consumer' found in the headers");
		return;
	}

	consumer_id = consumer_id.toLowerCase();
	if (! is_string_safe (consumer_id)) {
		END (res, 400, "Invalid 'consumer' field");
		return;
	}

	var group_name;
	if (! (group_name = req.headers.group)) {
		END (res, 400, "No 'group' found in the headers");
		return;
	}

	group_name = group_name.toLowerCase();
	if (! is_string_safe (group_name)) {
		END (res, 400, "Invalid 'group' field");
		return;
	}

	var valid_till; // in hours
	if (! (valid_till = req.headers["valid-till"])) {
		END (res, 400, "No 'valid-till' found in the headers");
		return;
	}

	try {
		valid_till = parseInt(valid_till,10);
	
		// 1 year max
		if (isNaN(valid_till) || valid_till < 0 || valid_till > 8760) {
			END (res, 400, "Invalid 'valid-till' field");
			return;
		}
	}
	catch (x)
	{
		END (res, 400, "Invalid 'valid-till' field");
		return;
	}

	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query (
		"INSERT INTO groups VALUES ($1::text, $2::text, $3::text,"	+
		"NOW() + '"							+
			valid_till + " hours')",
				[provider_id_in_db, consumer_id, group_name],
	(error, results) =>
	{
		if (error) {
			END (res, 500, "Could not add consumer to group");
			return;
		}

		END (res, 200, '');
		return;
	});
});

app.get('/auth/v1/group/list', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];
	var provider_id	= cert.subject.emailAddress.toLowerCase();

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);

			return;
		}
	}

	var group_name;
	if (! (group_name = req.headers.group)) {
		END (res, 400, "No 'group' found in the headers");
		return;
	}
	group_name = group_name.toLowerCase();

	if (! is_string_safe (group_name)) {
		END (res, 400, "Invalid 'group' field");
		return;
	}

	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query (
		"SELECT consumer, valid_till FROM groups "	+
		"WHERE id = $1::text "				+
		"AND group_name = $2::text "			+
		"AND valid_till > NOW()",
			[provider_id_in_db, group_name],
	(error, results) =>
	{
		if (error) {
			END (res, 500, "Could not select group");
			return;
		}

		var response = [];

		for (var row of results.rows) {
			response.push({"consumer":row.consumer, "valid-till":row.valid_till});
		}

		END (res, 200, JSON.stringify(response));
		return;
	});

});

app.post('/auth/v1/group/delete-consumer', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];
	var provider_id	= cert.subject.emailAddress.toLowerCase();

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);

			return;
		}
	}

	var consumer_id;
	if (! (consumer_id = req.headers.consumer)) {
		END (res, 400, "No 'consumer' found in the headers");
		return;
	}

	consumer_id = consumer_id.toLowerCase();
	if (! is_string_safe (consumer_id)) {
		END (res, 400, "Invalid 'consumer' field");
		return;
	}

	var group_name;
	if (! (group_name = req.headers.group)) {
		END (res, 400, "No 'group' found in the headers");
		return;
	}
	group_name = group_name.toLowerCase();

	if (! is_string_safe (group_name)) {
		END (res, 400, "Invalid 'group' field");
		return;
	}

	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query (
		"DELETE FROM groups "			+
		"WHERE id = $1::text "			+
		"AND consumer = $2::text "		+
		"AND group_name = $3::text",
			[provider_id_in_db, consumer_id, group_name],
	(error, results) =>
	{
		if (error) {
			END (res, 500, "Could not add to group");
			return;
		}

		if (results.rowCount === 0) {
			END (res, 400, "Consumer not in the group");
			return;
		}
		else {
			END (res, 200, '');
			return;
		}
	});
});

app.post('/auth/v1/group/delete', async function (req, res) {

	var error;
	if ((error = is_secure(req,res,null)) !== "OK") {
		END (res, 400, error);
		return;
	}

	var cert	= req.socket.getPeerCertificate();
	var cert_class	= cert.subject['id-qt-unotice'];
	var provider_id	= cert.subject.emailAddress.toLowerCase();

	if (cert_class)
	{
		cert_class = String(cert_class);

		try
		{
			cert_class = parseInt(cert_class.split(":")[1],10);
			if (cert_class < 3)
			{
				END (res, 403,
					"A class-3 or above certificate is "	+
					"required for calling policy related "	+
					"APIs"
				);

				return;
			}
		}
		catch(x)
		{
			END (res, 403,
				"A class-3 or above certificate is required "	+
				"for calling policy related APIs"
			);

			return;
		}
	}

	var group_name;
	if (! (group_name = req.headers.group)) {
		END (res, 400, "No 'group' found in the headers");
		return;
	}
	group_name = group_name.toLowerCase();

	if (! is_string_safe (group_name)) {
		END (res, 400, "Invalid 'group' field");
		return;
	}

	var email_domain	= provider_id.split("@")[1];

	var hash		= crypto.createHash('sha1').update(provider_id);
	var sha1_id		= hash.digest('hex');

	var provider_id_in_db	= sha1_id + "@" + email_domain;

	await pool.query (
		"DELETE FROM groups "	+
		"WHERE id = $1::text "	+
		"AND group_name = $2::text",
			[provider_id_in_db, group_name], (error, results) =>
	{
		if (error) {
			END (res, 500, "Could not delete group");
			return;
		}

		if (results.rowCount === 0) {
			END (res, 400, "No such group found");
			return;
		}

		END (res, 200,
			"Group with "			+
				results.rowCount	+
			" consumer(s) deleted"
		);

		return;
	});
});

app.get('/*', function (req, res) {
	var pathname = url.parse(req.url).pathname;
	console.log("=>>> GET  not found for :",pathname);
	END (res, 405, "");
	return;
});

app.post('/*', function (req, res) {
	var pathname = url.parse(req.url).pathname;
	console.log("=>>> POST not found for :",pathname);
	END (res, 405, "");
	return;
});

app.on('error', function(e) { 
	console.error(e); 
});

//////////////////////// RUN /////////////////////////////////

var num_cpus = os.cpus().length;

if (num_cpus < 4)
	num_cpus = 2;

// =============================== START preload code for chroot ==============

var _tmp;

_tmp = ["x can x x"].map(function (t) {
	return (parser.parse(t));
});

evaluator.evaluate(_tmp, {});

dns.lookup("www.google.com", {all:true}, (e, a) => {});

var _tmp = http_sync_request('GET', 'https://ca.iudx.org.in/crl');

// =============================== END preload code for chroot   ==============

function drop_privilege ()
{
	if (! do_drop_privilege)
		return;

	if (unveil)
	{
		if (EUID === 0) {
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

		log('green', `Worker ${process.pid} unveiled`);
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


	if (pledge)
		pledge.init (WORKER_PLEDGE);
}

if (cluster.isMaster)
{
	if (pledge)
		pledge.init (WORKER_PLEDGE + " unveil sendfd");

	log('green',`Master ${process.pid} is running`);

	for (var i = 0; i < num_cpus; i++) {
		cluster.fork();
	}

	cluster.on('exit', (worker, code, signal) => {
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
postgres_password = "";

//////////////////////////////////////////////////////////////
