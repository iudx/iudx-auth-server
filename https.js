/* vim: set ts=8 sw=4 tw=0 noet : */

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

const fs			= require("fs");
const os			= require("os");
const dns 			= require("dns");
const url			= require("url");
const cors			= require("cors");
const ocsp			= require("ocsp");
const Pool			= require("pg").Pool;
const https			= require("https");
const chroot			= require("chroot");
const crypto			= require("crypto");
const logger			= require("node-color-log");
const cluster			= require("cluster");
const express			= require("express");
const aperture			= require("./node-aperture");
const immutable			= require("immutable");
const geoip_lite		= require("geoip-lite");
const bodyParser		= require("body-parser");
const http_request		= require("request");
const pgNativeClient 		= require("pg-native");

const TOKEN_LENGTH		= 16;
const TOKEN_LENGTH_HEX		= 2 * TOKEN_LENGTH;

const EUID			= process.geteuid();
const is_openbsd		= os.type() === "OpenBSD";
const pledge 			= is_openbsd ? require("node-pledge")	: null;
const unveil			= is_openbsd ? require("openbsd-unveil"): null;

const SUCCESS			= '{"success":true}';
const NUM_CPUS			= os.cpus().length;
const SERVER_NAME		= "auth.iudx.org.in";

const MAX_TOKEN_TIME		= 31536000; // in seconds (1 year)
const MAX_TOKEN_HASH_LENGTH	= 64;
const MAX_SAFE_STRING_LENGTH	= 512;

const MIN_CERTIFICATE_CLASS_REQUIRED = immutable.Map({

	"/auth/v1/token/introspect"		: 1,

	"/auth/v1/certificate-info"		: 2,
	"/auth/v1/token"			: 2,
	"/auth/v1/token/confirm-payment"	: 2,
	"/auth/v1/credit"			: 2,
	"/auth/v1/credit/topup"			: 2,
	"/auth/v1/audit/credits"		: 2,

	"/auth/v1/audit/tokens"			: 3,
	"/auth/v1/token/revoke"			: 3,
	"/auth/v1/token/revoke-all"		: 3,
	"/auth/v1/acl"				: 3,
	"/auth/v1/acl/set"			: 3,
	"/auth/v1/acl/append"			: 3,
	"/auth/v1/group/add"			: 3,
	"/auth/v1/group/delete"			: 3,
	"/auth/v1/group/list"			: 3,
});

let has_started_serving_apis = false;

/* --- dns --- */

dns.setServers ([
	"1.1.1.1",
	"4.4.4.4",
	"8.8.8.8",
	"[2001:4860:4860::8888]",
	"[2001:4860:4860::8844]",
]);

/* --- telegram --- */

const telegram_apikey	= fs.readFileSync ("telegram.apikey","ascii").trim();
const telegram_chat_id	= fs.readFileSync ("telegram.chatid","ascii").trim();

const telegram_url	= "https://api.telegram.org/bot" + telegram_apikey +
				"/sendMessage?chat_id="	+ telegram_chat_id +
				"&text=";

/* --- postgres --- */

const DB_SERVER	= "127.0.0.1";

const USERS = [
	"select.crl",

	"select.token",
	"insert.token",
	"update.token",

	"select.policy",
	"insert.policy",
	"update.policy",

	"select.groups",
	"insert.groups",
	"update.groups",
];

const db = {
	async	: {select:{}, insert:{}, update:{}},
	sync	: {select:{}, insert:{}, update:{}}
};

const password	= {};

for (const u of USERS)
{
	password[u] = fs.readFileSync (
			"passwords/"+ u +".db.password",
			"ascii"
	).trim();

	const action	= u.split(".")[0];
	const table	= u.split(".")[1];

	db.async [action][table] = new Pool ({
		host		: DB_SERVER,
		port		: 5432,
		user		: u,
		database	: "postgres",
		password	: password[u],
	});

	db.async[action][table].connect();

	// sync queries are only for:
	// SELECTing any table -OR- to UPDATE the token table 

	if (
		(action === "select")	||
		(action === "update" && table === "token")
	)
	{
		db.sync[action][table] = new pgNativeClient();

		db.sync[action][table].connectSync (
		"postgresql://" +u+ ":" +password[u]+ "@" + DB_SERVER + ":5432/postgres",
			function(err)
			{
				if(err) {
					throw err;
				}
			}
		);

		db.sync[action][table].query = db.sync[action][table].querySync;
	}

	delete password[u]; // forget the password
}

const select = {

	token : {
		async	: db.async.select.token.query,
		sync	: db.sync.select.token.querySync,
	},

	crl : {
		async	: db.async.select.token.query,
	},

	policy : {
		async	: db.async.select.token.query,
		sync	: db.sync.select.policy.querySync,
	},

	groups : {
		async	: db.async.select.token.query,
		sync	: db.sync.select.groups.querySync,
	}
};

const insert = {

	token : {
		async	: db.async.select.token.query,
		sync	: db.sync.select.groups.querySync,
	}
};

const update = {
	
	token : {
		async	: db.async.update.token.query,
		sync	: db.sync.update.token.query,
	}
};

/* --- express --- */

const app = express();
app.use (
	cors ({
		methods		: ["POST"],
		credentials	: true,
		origin		: function (origin, callback)
				{
					callback(null, origin ? true : false);
				}
	})
);

app.use(bodyParser.raw({type:"*/*"}));
app.use(security);

app.disable("x-powered-by");

/* --- aperture --- */

const apertureOpts = {

    types	: aperture.types,
    typeTable	: {

        ip				: "ip",
	time				: "time",

	tokens_per_day			: "number",	// tokens issued today

	api				: "string",	// the API to be called
	method				: "string",	// the method for API

	"cert.class"			: "number",	// the certificate class
	"cert.cn"			: "string",
	"cert.o"			: "string",
	"cert.ou"			: "string",
	"cert.c"			: "string",
	"cert.st"			: "string",
	"cert.gn"			: "string",
	"cert.sn"			: "string",
	"cert.title"			: "string",

	"cert.issuer.cn"		: "string",
	"cert.issuer.email"		: "string",
	"cert.issuer.o"			: "string",
	"cert.issuer.ou"		: "string",
	"cert.issuer.c"			: "string",
	"cert.issuer.st"		: "string",

	groups				: "string",	// CSV actually

	country				: "string",
	region				: "string",
	timezone			: "string",
	city				: "string",
	latitude			: "number",
	longitude			: "number",
    }
};

const parser	= aperture.createParser		(apertureOpts);
const evaluator	= aperture.createEvaluator	(apertureOpts);

/* --- https --- */

const trusted_CAs = [
	fs.readFileSync("ca.iudx.org.in.crt"),
	fs.readFileSync("/etc/ssl/cert.pem"),
	fs.readFileSync("CCAIndia2015.cer"),
	fs.readFileSync("CCAIndia2014.cer"),
];

const https_options = {
	key			: fs.readFileSync("https-key.pem"),
	cert			: fs.readFileSync("https-certificate.pem"),
	ca			: trusted_CAs,
	requestCert		: true,
	rejectUnauthorized	: true,
};

/* --- functions --- */

function log(color, msg)
{
	const message = new Date() + " | " + msg;

	if (color === "red") {
		send_telegram(message);
	}

	logger.color(color).log(message);
}

function send_telegram (message)
{
	http_request ( telegram_url + "[ AUTH ] : " + message,
		function (error, response, body)
		{
			if (error)
			{
				log ("yellow",
					"Telegram failed ! response = " +
						String(response)	+
					" body = "			+
						String(body)
				);
			}
		}
	);
}

function END_SUCCESS (res, http_status, msg)
{
	res.setHeader("Content-Type", "application/json");
	res.status(http_status).end(msg + "\n");
}

function END_ERROR (res, http_status, msg, exception = null)
{
	if (exception)
		log("red", String(exception).replace(/\n/g," "));

	res.setHeader("Content-Type", "application/json");
	res.setHeader("Connection", "close");

	res.status(http_status).end('{"error":"' + msg + '"}\n');

	res.socket.end();
	res.socket.destroy();
}

function is_valid_email (email)
{
	if (! email || typeof email !== "string")
		return false;

	if (email.length < 5 || email.length > 64)
		return false;

	let num_ats	= 0;
	let num_dots	= 0;

	for (const chr of email)
	{
		if (
			(chr >= "a" && chr <= "z") ||
			(chr >= "A" && chr <= "Z") ||
			(chr >= "0" && chr <= "9")
		)
		{
			// ok;
		}
		else
		{
			switch (chr)
			{
				case "-":
				case "_":
					break;

				case "@":
					++num_ats;
					break;

				case ".":
					++num_dots;
					break;

				default:
					return false;
			}
		}
	}

	if (num_ats !== 1 || num_dots < 1)
		return false;

	return true;
}

function is_certificate_ok (req, cert, validate_email)
{
	if ((! cert) || (! cert.subject))
		return "Invalid certificate. No subject found";

	if (validate_email)
	{
		if (! is_valid_email(cert.subject.emailAddress))
			return "Invalid emailAddress field in the certificate";
	}

	if ((! cert.issuer) || (! cert.issuer.emailAddress))
		return "Certificate issuer has no emailAddress field";

	const issuer_email = cert.issuer.emailAddress.toLowerCase();

	if (! is_valid_email(issuer_email))
		return "Certificate issuer's emailAddress is invalid";

	if (issuer_email.startsWith("iudx.sub.ca@"))
	{
		const issued_to_domain	= cert.subject.emailAddress
						.toLowerCase()
						.split("@")[1];

		const issuer_domain	= issuer_email
						.toLowerCase()
						.split("@")[1];

		if (issuer_domain !== issued_to_domain)
		{
			log ("red",
				"Invalid certificate: issuer = "+
					issuer_domain		+
				" and issued to = "		+
					cert.subject.emailAddress
			);

			return "Invalid certificate issuer";
		}
	}

	return "OK";
}

function is_secure (req, res, cert, validate_email = true)
{
	if (req.headers.origin)
	{
		const origin = req.headers.origin.toLowerCase();

		// e.g Origin = https://www.iudx.org.in:8443/

		if (! origin.startsWith("https://"))
			return "Insecure 'origin' field";

		if ((origin.match(/\//g) || []).length < 2)
			return "Invalid 'origin' field";

		const origin_domain = String (
			origin
				.split("/")[2]	// remove protocol
				.split(":")[0]	// remove port number
		);

		if (! origin_domain.endsWith(".iudx.org.in"))
			return "Invalid 'origin' field in the header";

		res.header("X-XSS-Protection", "1; mode=block");
		res.header("X-Frame-Options", "deny");
		res.header("X-Content-Type-Options","nosniff");
		res.header("Referrer-Policy","no-referrer-when-downgrade");

		res.header("Access-Control-Allow-Origin", req.headers.origin);
		res.header("Access-Control-Allow-Methods", "POST");
	}

	const error = is_certificate_ok (req,cert,validate_email);

	if (error !== "OK")
		return "Invalid certificate. " + error;

	return "OK";
}

function has_certificate_been_revoked (socket, cert, CRL)
{
	const cert_fingerprint	= cert.fingerprint
					.replace(/:/g,"")
					.toLowerCase();

	const cert_serial	= cert.serialNumber
					.toLowerCase()
					.replace(/^0+/,"");

	const cert_issuer	= cert.issuer.emailAddress.toLowerCase();

	for (const c of CRL)
	{
		c.issuer	= c.issuer.toLowerCase();
		c.serial	= c.serial.toLowerCase().replace(/^0+/,"");
		c.fingerprint	= c.fingerprint.toLowerCase().replace(/:/g,"");

		if (
			(c.issuer	=== cert_issuer)	&&
			(c.serial	=== cert_serial)	&&
			(c.fingerprint	=== cert_fingerprint)
		)
		{
			return true;
		}
	}

	// If it was issued by a sub-CA then check the sub-CA's cert too
	// Assuming depth is <= 3. ca@iudx.org.in -> sub-CA -> user

	if (cert_issuer !== "ca@iudx.org.in")
	{
		const ISSUERS = [];

		if (cert.issuerCertificate)
		{
			// both CA and sub-CA are the issuers
			ISSUERS.push(cert.issuerCertificate);

			if (cert.issuerCertificate.issuerCertificate)
			{
				ISSUERS.push (
					cert.issuerCertificate.issuerCertificate
				);
			}
		}
		else
		{
			/*
				if the issuerCertificate is empty,
				then the session must have been reused
				by the browser.
			*/

			if (! socket.isSessionReused())
				return true;
		}

		for (const issuer of ISSUERS)
		{
			if (issuer.fingerprint && issuer.serialNumber)
			{
				const issuer_fingerprint = issuer
								.fingerprint
								.replace(/:/g,"")
								.toLowerCase();

				const issuer_serial = issuer
							.serialNumber
							.toLowerCase();

				for (const c of CRL)
				{
					if (c.issuer === "ca@iudx.org.in")
					{
						const crl_serial = c.serial
									.toLowerCase()
									.replace(/^0+/,"");

						const crl_fingerprint = c.fingerprint
									.replace(/:/g,"")
									.toLowerCase();

						if (crl_serial === issuer_serial && crl_fingerprint === issuer_fingerprint)
							return true;
					}
				}
			}
			else
			{
				/*
					if fingerprint OR serial is undefined,
					then the session must have been reused
					by the browser.
				*/

				if (! socket.isSessionReused())
					return true;
			}
		}
	}

	return false;
}

function is_string_safe (str, exceptions = "")
{
	if (! str || typeof str !== "string")
		return false;

	if (str.length === 0 || str.length > MAX_SAFE_STRING_LENGTH)
		return false;

	exceptions = exceptions + "-/.@";

	for (const ch of str)
	{
		if (
			(ch >= "a" && ch <= "z") ||
			(ch >= "A" && ch <= "Z") ||
			(ch >= "0" && ch <= "9")
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

function is_iudx_certificate(cert)
{
	if (! cert.issuer.emailAddress)
		return false;

	const issuer = cert
			.issuer
			.emailAddress
			.toLowerCase();

	return (
		(issuer === "ca@iudx.org.in") || issuer.startsWith("iudx.sub.ca@")
	);
}

function body_to_json (body)
{
	if (! body)
		return {};

	let string_body;

	try
	{
		string_body = Buffer
				.from(body,"utf-8")
				.toString("ascii")
				.trim();

		if (string_body.length === 0)
			return {};
	}
	catch (x)
	{
		return {};
	}

	try
	{
		const json_body = JSON.parse (string_body);

		if (json_body)
			return json_body;
		else
			return {};
	}
	catch (x)
	{
		return null;
	}
}

function security (req, res, next)
{
	if (! has_started_serving_apis)
	{
		if (is_openbsd) // drop "rpath"
			pledge.init("error stdio tty prot_exec inet dns recvfd");

		has_started_serving_apis = true;
	}

	req.setTimeout(5000);

	const api = url.parse(req.url).pathname;

	// Not an API !
	if ((! api.startsWith("/auth/v1/")))
		return next();

	const cert		 = req.socket.getPeerCertificate(true);
	const min_class_required = MIN_CERTIFICATE_CLASS_REQUIRED.get(api);

	if (! min_class_required)
	{
		return END_ERROR (
			res, 404,
				"No such API. Please visit: "	+
				"<http://auth.iudx.org.in> for documentation."
		);
	}

	cert.serialNumber	= cert.serialNumber.toLowerCase();
	cert.fingerprint	= cert.fingerprint.toLowerCase();

	if (is_iudx_certificate(cert))
	{
		let	integer_cert_class	= 0;
		const	cert_class		= cert.subject["id-qt-unotice"];

		if (cert_class)
		{
			integer_cert_class = parseInt(
				cert_class.split(":")[1],10
			) || 0;
		}

		if (integer_cert_class < 1)
			return END_ERROR(res, 403, "Invalid certificate class");

		if (integer_cert_class < min_class_required)
		{
			return END_ERROR (
				res, 403,
					"A class-" + min_class_required	+
					" or above certificate "	+
					"is required to call this API"
			);
		}

		if (api.endsWith("/introspect") && integer_cert_class !== 1)
		{
			return END_ERROR (
				res, 403,
					"A class-1 certificate is required " +
					"to call this API"
			);
		}

		const error = is_secure(req,res,cert);

		if (error !== "OK")
			return END_ERROR (res, 403, error);

		select.crl.async (
			"SELECT crl FROM crl LIMIT 1", [], (error,results) =>
			{
				if (error || results.rows.length === 0)
				{
					return END_ERROR (
						res, 500,
						"Internal error!", error
					);
				}

				const CRL = results.rows[0].crl;

				if (has_certificate_been_revoked(req.socket,cert,CRL))
				{
					return END_ERROR (
						res, 403,
						"Certificate has been revoked"
					);
				}

				if (! (res.locals.body = body_to_json(req.body)))
				{
					return END_ERROR (
						res, 400,
						"Body is not a valid JSON"
					);
				}

				res.locals.cert		= cert;
				res.locals.cert_class	= integer_cert_class;
				res.locals.email	= cert
								.subject
								.emailAddress
								.toLowerCase();

				return next();
			}
		);
	}
	else
	{
		ocsp.check({cert:cert.raw, issuer:cert.issuerCertificate.raw},
			function (err, ocsp_response)
			{
				if (err)
				{
					return END_ERROR (
						res, 403,
						"Your certificate issuer did "	+
						"NOT respond to an OCSP request"
					);
				}

				if (ocsp_response.type !== "good")
				{
					return END_ERROR (
						res, 403,
						"Your certificate has been "	+
						"revoked by your certificate issuer"
					);
				}

				// certificate may not have a "emailAddress" field

				const error = is_secure(req,res,cert,false);

				if (error !== "OK")
					return END_ERROR (res, 403, error);

				res.locals.cert_class	= 1;
				res.locals.email	= "";

				if (is_valid_email(cert.subject.emailAddress))
				{
					res.locals.cert_class	= 2;
					res.locals.email	= cert
									.subject
									.emailAddress
									.toLowerCase();
				}

				if (res.locals.cert_class < min_class_required)
				{
					return END_ERROR (
						res, 403,
						"A class-" + min_class_required		+
						" or above certificate is required "	+
						"to call this API"
					);
				}

				if (! (res.locals.body = body_to_json(req.body)))
				{
					return END_ERROR (
						res, 400,
						"Body is not a valid JSON"
					);
				}

				res.locals.cert	= cert;

				return next();
			}
		);
	}
}

function object_to_array (o)
{
	if (o instanceof Object)
	{
		if (o instanceof Array)
			return o;
		else
			return [o];
	}

	return null;
}

/* --- APIs --- */

app.post("/auth/v1/token", function (req, res) {

	const cert				= res.locals.cert;
	const cert_class			= res.locals.cert_class;
	const body				= res.locals.body;
	const consumer_id			= res.locals.email;

	const response_array 			= [];
	const resource_id_dict			= {};
	const resource_server_token 		= {};
	const sha256_of_resource_server_token	= {};

	const request_array			= object_to_array(body.request);

	if (! request_array)
		return END_ERROR(res, 400, "'request' field is not a valid JSON");

	const token_rows = select.token.sync (

		"SELECT COUNT(*)/60.0 "	+
		"AS rate "		+
		"FROM token "		+
		"WHERE id = $1::text "	+
		"AND issued_at >= (NOW() - interval '60 seconds')",
			[consumer_id],
	);

	// in last 1 minute
	const tokens_rate_per_second = parseFloat (token_rows[0].rate);

	if (tokens_rate_per_second > 1) // tokens per second
	{
		log ("red",
			"Too many requests from user : " + consumer_id +
			", from ip : " + String (req.connection.remoteAddress)
		);

		return END_ERROR (res, 429, "Too many requests");
	}

	const ip	= req.connection.remoteAddress;
	const geo	= geoip_lite.lookup(ip) || {ll:[]};
	const issuer	= cert.issuer;

	const context = {

		principal	: consumer_id,
		action		: "access",

		conditions	: {
			ip			: ip,
			time			: new Date(),

			"cert.class"		: cert_class,
			"cert.cn"		: cert.subject.CN 	|| "",
			"cert.o"		: cert.subject.O	|| "",
			"cert.ou"		: cert.subject.OU	|| "",
			"cert.c"		: cert.subject.C	|| "",
			"cert.st"		: cert.subject.ST	|| "",
			"cert.gn"		: cert.subject.GN	|| "",
			"cert.sn"		: cert.subject.SN	|| "",
			"cert.title"		: cert.subject.title	|| "",

			"cert.issuer.cn"	: issuer.CN		|| "",
			"cert.issuer.email"	: issuer.emailAddress	|| "",
			"cert.issuer.o"		: issuer.O		|| "",
			"cert.issuer.ou"	: issuer.OU		|| "",
			"cert.issuer.c"		: issuer.C		|| "",
			"cert.issuer.st"	: issuer.ST		|| "",

			country		 	: geo.country		|| "",
			region			: geo.region		|| "",
			timezone		: geo.timezone		|| "",
			city			: geo.city		|| "",
			latitude		: geo.ll[0]		||  0,
			longitude		: geo.ll[1]		||  0,
		}
	};

	let requested_token_time;		// as specified by the consumer
	let token_time = MAX_TOKEN_TIME;	// to be sent along with token

	if (body["token-time"])
	{
		requested_token_time = parseInt(body["token-time"],10);

		if (
			isNaN(requested_token_time)		||
			requested_token_time < 1		||
			requested_token_time > MAX_TOKEN_TIME
		)
		{
			return END_ERROR (
				res, 400,
				"'token-time' field should be > 0 and < " +
				MAX_TOKEN_TIME
			);
		}
	}

	const existing_token		= body["existing-token"];
	const providers			= {};

	let num_rules_passed		= 0;
	let total_data_cost_per_second	= 0.0;

	const payment_info		= {};

	for (const row of request_array)
	{
		let resource = row["resource-id"];

		if (! is_string_safe(resource, "*_")) // allow some chars
		{
			return END_ERROR (
				res, 400,
				"Invalid 'resource-id "		+
				"(contains unsafe chars)' : "	+ resource
			);
		}

		if (typeof row.method === "string")
			row.methods = [row.method];

		if (! row.methods)
			row.methods = ["*"];

		if ( ! (row.methods instanceof Array))
		{
			return END_ERROR (res, 400,
				"Invalid 'methods' for resource id:" +
				resource
			);
		}

		if (row.api && typeof row.api === "string")
			row.apis = [row.api];

		if (! row.apis)
			row.apis = ["/*"];

		if ( ! (row.apis instanceof Array))
		{
			return END_ERROR (res, 400,
				"Invalid 'apis' for resource id:" +
				resource
			);
		}

		if (row.provider) // the resource-id is not in the catalog ?
		{
			if (typeof row.provider !== "string")
			{
				return END_ERROR (res, 400,
					"Invalid 'provider': " + row.provider
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
								.digest("hex");

			resource =	provider_email_domain 		+
						"/"			+
					sha1_of_provider_email_id	+
						"/"			+
					resource;
		}

		if ((resource.match(/\//g) || []).length < 3)
		{
			return END_ERROR (res, 400,
				"Invalid 'resource-id' "		+
				"(it must have at least 3 '/' chars): "	+
					resource
			);
		}

		// if body is given but is not a valid object
		if (row.body && (! (row.body instanceof Object)))
		{
			return END_ERROR (res, 400,
				"Invalid body for id :" + resource
			);
		}

		const split 			= resource.split("/");

		const provider_id_in_db		= split[1] + "@" + split[0];
		const resource_server		= split[2];
		const resource_name		= split.slice(3).join("/");

		providers			[provider_id_in_db]	= true;

		// to be generated later
		resource_server_token		[resource_server]	= true;

		// to be generated later
		sha256_of_resource_server_token	[resource_server]	= true;

		const policy_rows = select.policy.sync (

			"SELECT policy,policy_in_json FROM policy " +
			"WHERE id = $1::text LIMIT 1",
				[provider_id_in_db]
		);

		if (policy_rows.length === 0)
		{
			return END_ERROR (res, 400,
				"Invalid 'resource-id (no policy found)': " +
					resource
			);
		}

		const policy_in_text = Buffer.from (
						policy_rows[0].policy, "base64"
					)
					.toString("ascii")
					.toLowerCase();

		const policy_in_json	= policy_rows[0].policy_in_json;

		// full name of resource eg: bangalore.domain.com/streetlight-1
		context.resource = resource_server + "/" + resource_name;

		context.conditions.groups = "";

		if (policy_in_text.search(" consumer-in-group") > 0)
		{
			const group_rows = select.groups.sync (

				"SELECT DISTINCT group_name "	+
				"FROM groups "			+
				"WHERE id = $1::text "		+
				"AND consumer = $2::text "	+
				"AND valid_till > NOW()",
				[
					provider_id_in_db,	// 1
					consumer_id		// 2
				]
			);

			const group_array = [];
			for (const g of group_rows)
				group_array.push(g.group_name);

			context.conditions.groups = group_array.join();
		}

		context.conditions.tokens_per_day = 0;

		if (policy_in_text.search(" tokens_per_day ") > 0)
		{
			const resource_true = {};
				resource_true [resource] = true;

			const tokens_per_day_rows = select.token.sync (

				"SELECT COUNT(*) FROM token "		+
				"WHERE id = $1::text "			+
				"AND resource_ids @> $2::jsonb "	+
				"AND issued_at >= DATE_TRUNC('day',NOW())",
				[
					consumer_id,			// 1
					JSON.stringify(resource_true),	// 2
				],
			);

			context.conditions.tokens_per_day = parseInt (
				tokens_per_day_rows[0].count, 10
			);
		}

		let CTX = context;

		if (row.body && policy_in_text.search(" body.") > 0)
		{
			// deep copy
			CTX = JSON.parse(JSON.stringify(context));

			for (const key in row.body)
				CTX.conditions["body." + key] = row.body[key];
		}

		for (const api of row.apis)
		{
			if (typeof api !== "string")
			{
				return END_ERROR (
					res, 400, "Invalid 'api' :" + api
				);
			}

			CTX.conditions.api = api;

			for (const method of row.methods)
			{
				if (typeof method !== "string")
				{
					return END_ERROR (res, 400,
						"Invalid 'method' :" + method
					);
				}

				CTX.conditions.method = method;

				try
				{
					// token expiry time as specified by the provider
					// in the policy

					const result = evaluator.evaluate (
						policy_in_json,
						CTX
					);

					const token_time_in_policy	= result.expiry;
					const payment_amount		= result.amount;
					// const payment_currency	= result.currency;

					if ((! token_time_in_policy) || token_time_in_policy < 0 || payment_amount < 0)
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

					const cost_per_second		= payment_amount / token_time_in_policy;

					total_data_cost_per_second	+= cost_per_second;

					if (! payment_info[provider_id_in_db])
						payment_info[provider_id_in_db] = 0.0;

					payment_info[provider_id_in_db]	+= cost_per_second;

					token_time = Math.min (
						token_time,
						token_time_in_policy
					);

				}
				catch (x)
				{
					return END_ERROR (res, 403,
						"Unauthorized to access :'"	+
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
			token_time = Math.min(requested_token_time,token_time);

		const response = {
			"resource-id"	: resource,
			"methods"	: row.methods,
			"apis"		: row.apis,
			"body"		: row.body ? row.body : null,
		};

		response_array.push (response);

		resource_id_dict[resource] = true;

		++num_rules_passed;
	}

	if ((num_rules_passed < 1) || (num_rules_passed < request_array.length))
		return END_ERROR (res, 403, "Unauthorized!");

	let token;
	let existing_row;

	if (existing_token)
	{
		if (
			(! is_string_safe(existing_token))	||
			(! existing_token.startsWith(SERVER_NAME + "/"))
		)
		{
			return END_ERROR (
				res, 400, "Invalid 'existing-token' field"
			);
		}

		if ((existing_token.match(/\//g) || []).length !== 2)
		{
			return END_ERROR (
				res, 400, "Invalid 'existing-token' field"
			);
		}

		const issued_by			= existing_token.split("/")[0];
		const issued_to			= existing_token.split("/")[1];
		const random_part_of_token	= existing_token.split("/")[2];

		if (
			(issued_by 			!== SERVER_NAME)	||
			(issued_to			!== consumer_id)	||
			(random_part_of_token.length	!== TOKEN_LENGTH_HEX)
		) {
			return END_ERROR (res, 403, "Invalid existing-token");
		}

		const sha256_of_existing_token	= crypto.createHash("sha256")
							.update(random_part_of_token)
							.digest("hex");

		existing_row = select.token.sync (

			"SELECT EXTRACT(EPOCH FROM (expiry - NOW())) "	+
			"AS token_time,request,resource_ids,"		+
			"server_token "					+
			"FROM token WHERE "				+
			"id = $1::text AND "				+
			"token = $2::text AND "				+
			"revoked = false AND "				+
			"expiry > NOW() LIMIT 1",
			[
				consumer_id,			// 1
				sha256_of_existing_token,	// 2
			]
		);

		if (existing_row.length === 0)
		{
			return END_ERROR (res, 403,
				"Invalid 'existing-token' field"
			);
		}

		token_time = Math.min (
			token_time,
			(parseInt(existing_row[0].token_time, 10) || 0)
		);

		for (const key in existing_row[0].server_token)
			resource_server_token [key] = true;

		token = random_part_of_token; // given by the user
	}
	else
	{
		token = crypto.randomBytes(TOKEN_LENGTH).toString("hex");
	}

	const response = {

		/* Token format: issued-by / issued-to / token */

		"token"		: SERVER_NAME + "/" + consumer_id + "/" + token,
		"token-type"	: "IUDX",
		"expires-in"	: token_time,

		"payment-info"	: {
			"amount"	: 0.0,
			"currency"	: "INR",
		},

	};

	const total_payment_amount	= total_data_cost_per_second * token_time;
	const balance_amount_in_credit	= 0.0; // TODO get from DB

	if (total_payment_amount > 0)
	{
		if (total_payment_amount > balance_amount_in_credit)
			return END_ERROR (res, 402, "Not enough balance in credits for INR : " + total_payment_amount);

		response["payment-info"].amount = total_payment_amount;

		// TODO save payment info
	}

	const num_resource_servers = Object
					.keys(resource_server_token)
					.length;

	if (num_resource_servers > 1)
	{
		for (const key in resource_server_token)
		{
			resource_server_token[key] = crypto
							.randomBytes(TOKEN_LENGTH)
							.toString("hex");

			sha256_of_resource_server_token[key] = crypto
								.createHash("sha256")
								.update(resource_server_token[key])
								.digest("hex");
		}
	}

	response["server-token"] = resource_server_token;

	const sha256_of_token	= crypto.createHash("sha256")
					.update(token)
					.digest("hex");
	let query;
	let parameters;

	if (existing_token)
	{
		// merge both existing values

		const old_request 	= existing_row[0].request;
		const new_request	= old_request.concat(request_array);

		const new_resource_ids_dict = Object.assign(
			{}, existing_row[0].resource_ids, resource_id_dict
		);

		query = "UPDATE token SET " 				+
				"request = $1::jsonb,"			+
				"resource_ids = $2::jsonb,"		+
				"server_token = $3::jsonb,"		+
				"expiry = NOW() + $4::interval " 	+
				"WHERE "				+
				"id = $5::text AND "			+
				"token = $6::text AND "			+
				"expiry > NOW()";

		parameters = [
			JSON.stringify(new_request),			// 1
			JSON.stringify(new_resource_ids_dict),		// 2
			JSON.stringify(sha256_of_resource_server_token),// 3
			token_time + " seconds",			// 4
			consumer_id,					// 5
			sha256_of_token,				// 6
		];

		update.token.async (query, parameters, (error,results) =>
		{
			if (error || results.rowCount === 0)
				return END_ERROR (res, 500, "Internal error!", error);

			return END_SUCCESS (
				res, 200, JSON.stringify(response)
			);
		});
	}
	else
	{
		const request = response_array;

		query = "INSERT INTO token VALUES(" 			+
				"$1::text,"				+
				"$2::text,"				+
				"NOW() + $3::interval,"			+
				"$4::jsonb,"				+
				"$5::text,"				+
				"$6::text,"				+
				"NOW(),"				+
				"$7::jsonb,"				+
				"false,"				+
				"false,"				+
				"$8::int,"				+
				"$9::jsonb,"				+
				"$10::jsonb"				+
			")";

		parameters = [
			consumer_id,					// 1
			sha256_of_token,				// 2
			token_time + " seconds",			// 3
			JSON.stringify(request),			// 4
			cert.serialNumber,				// 5
			cert.fingerprint,				// 6
			JSON.stringify(resource_id_dict),		// 7
			cert_class,					// 8
			JSON.stringify(sha256_of_resource_server_token),// 9
			JSON.stringify(providers)			// 10
		];

		insert.token.async (query, parameters, (error,results) =>
		{
			if (error || results.rowCount === 0)
				return END_ERROR (res, 500, "Internal error!", error);

			return END_SUCCESS (
				res, 200, JSON.stringify(response)
			);
		});
	}

});

app.post("/auth/v1/token/confirm-payment", function (req, res) {
	// TODO
});

app.post("/auth/v1/credit", function (req, res) {

	// TODO

	// if class 2 - only related to this certificate's public key
	// if class 3 or above - for all ids with this emailAddress

	// select amount from credits table
});

app.post("/auth/v1/credit/topup", function (req, res) {

	// TODO

	// if class 2 - only related to this certificate's public key
	// if class 3 or above - for all ids with this emailAddress

	// insert or update amount in credit table
});

app.post("/auth/v1/audit/credits", function (req, res) {

	// TODO

	// if class 2 - only related to this certificate's public key
	// if class 3 or above - for all ids with this emailAddress
});

app.post("/auth/v1/token/introspect", function (req, res) {

	const cert	= res.locals.cert;
	const body	= res.locals.body;

	if (! body.token)
		return END_ERROR (res, 400, "No 'token' found in the body");

	const token = body.token;

	if ((! is_string_safe(token)) || (! token.startsWith(SERVER_NAME + "/")))
		return END_ERROR (res, 400, "Invalid 'token' field");

	if ((token.match(/\//g) || []).length !== 2)
		return END_ERROR (res, 400, "Invalid 'token' field");

	let server_token = body["server-token"] || true;

	if (server_token === true || server_token === "true")
	{
		server_token = true;
	}
	else if (
		(! is_string_safe(server_token))	||
		(server_token.length !== TOKEN_LENGTH_HEX)
	)
	{
		return END_ERROR (res, 400, "Invalid 'server-token' field");
	}

	const consumer_request = body.request;

	if (consumer_request)
	{
		if (! (consumer_request instanceof Array))
			return END_ERROR (res, 400, "'request' must be an array");
	}

	const issued_by			= token.split("/")[0];
	const issued_to			= token.split("/")[1];
	const random_part_of_token	= token.split("/")[2];

	if (
		(issued_by 			!== SERVER_NAME)	||
		(random_part_of_token.length	!== TOKEN_LENGTH_HEX)	||
		(! is_valid_email(issued_to))
	) {
		return END_ERROR (res, 400, "Invalid token");
	}

	const sha256_of_token	= crypto.createHash("sha256")
					.update(random_part_of_token)
					.digest("hex");

	const	ip 		= req.connection.remoteAddress;
	let	ip_matched	= false;

	if ((! cert.subject) || (! is_string_safe(cert.subject.CN)))
		return END_ERROR (res, 400, "Invalid CN in the certificate");

	const resource_server_name_in_cert = cert.subject.CN.toLowerCase();

	dns.lookup(resource_server_name_in_cert, {all:true},
	(error, ip_addresses) =>
	{
		if (error)
		{
			return END_ERROR (
				res, 400,
				"Invalid hostname : " + resource_server_name_in_cert
			);
		}

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
				"Your certificate hostname in CN and " +
				"your IP does not match!"
			);
		}

		// TODO select payment_required from token table

		select.token.async (

			"SELECT expiry,request,cert_class,"	+
			"server_token,providers "		+
			"FROM token "				+
			"WHERE id = $1::text "			+
			"AND token = $2::text "			+
			"AND revoked = false "			+
			"AND expiry > NOW() LIMIT 1",
			[
				issued_to,	// 1
				sha256_of_token	// 2
			],

		(error, results) =>
		{
			if (error)
				return END_ERROR (res, 500, "Internal error!", error);

			if (results.rows.length === 0)
				return END_ERROR (res, 403, "Invalid token");

			const expected_server_token = results
							.rows[0]
							.server_token[resource_server_name_in_cert];

			// if token doesn't belong to this server
			if (! expected_server_token)
				return END_ERROR (res, 403, "Invalid token");

			const num_resource_servers = Object.keys (
				results.rows[0].server_token
			).length;

			if (num_resource_servers > 1)
			{
				if (server_token === true) // should be a real token
				{
					return END_ERROR (
						res, 403,
						"Invalid 'server-token' field in the body"
					);
				}

				const sha256_of_server_token = crypto.createHash("sha256")
								.update(server_token)
								.digest("hex");

				if (sha256_of_server_token !== expected_server_token)
				{
					return END_ERROR (
						res, 403,
						"Invalid 'server-token' field in the body"
					);
				}
			}
			else
			{
				// token belongs to only 1 server

				if (server_token === true && expected_server_token === true)
				{
					// ok
				}
				else if (typeof expected_server_token === "string")
				{
					const sha256_of_server_token = crypto.createHash("sha256")
									.update(server_token)
									.digest("hex");

					if (sha256_of_server_token !== expected_server_token)
					{
						return END_ERROR (
							res, 403,
							"Invalid 'server-token' field in the body"
						);
					}
				}
				else
				{
					return END_ERROR (
						res, 500,
						"Invalid 'expected_server_token' in DB"
					);
				}
			}

			const request	= results.rows[0].request;
			const providers	= results.rows[0].providers;

			const request_for_resource_server = [];

			for (const r of request)
			{
				const split		= r["resource-id"].split("/");
				const provider 		= split[1] + "@" + split[0];
				const resource_server	= split[2];

				if (providers[provider]) // if provider exists in providers dictionary
				{
					if (resource_server === resource_server_name_in_cert)
						request_for_resource_server.push (r);
				}
			}

			if (request_for_resource_server.length === 0)
				return END_ERROR (res, 403, "Invalid token");

			if (consumer_request)
			{
				const l1 = Object
						.keys(consumer_request)
						.length;

				const l2 = Object
						.keys(request_for_resource_server)
						.length;

				// more number of requests than what is allowed

				if (l1 > l2)
					return END_ERROR (res, 403, "Unauthorized !");

				for (const r1 of consumer_request)
				{
					if (! (r1 instanceof Object))
						return END_ERROR (res, 400, "Invalid request : " + r1);

					// default values

					if (! r1.methods)
						r1.methods = ["*"];

					if (! r1.apis)
						r1.apis = ["/*"];

					const keys1 = Object
							.keys(request);

					let resource_found = false;

					for (const r2 of request_for_resource_server)
					{
						if (r1["resource-id"] === r2["resource-id"])
						{
							const keys2 = Object
								.keys(request_for_resource_server);

							const keys = new Set(keys1.concat(keys2));

							for (const k of keys)
							{
								if (JSON.stringify(r1[k]) !== JSON.stringify(r2[k]))
									return END_ERROR (res, 403, "Unauthorized to access : " + r1["resource-id"] + " for key : " + k);
							}

							resource_found = true;
							break;
						}
					}

					if (! resource_found)
						return END_ERROR (res, 403, "Unauthorized to access " + JSON.stringify(r1));
				}
			}

			const response = {
				"consumer"			: issued_to,
				"expiry"			: results.rows[0].expiry,
				"request"			: request_for_resource_server,
				"consumer-certificate-class"	: results.rows[0].cert_class,
			};

			update.token.async (

				"UPDATE token SET introspected = true "		+
				"WHERE token = $1::text "			+
				"AND revoked = false "				+
				"AND expiry > NOW()",
					[sha256_of_token],

				(error_1, results_1) =>
				{
					if (error_1 || results_1.rowCount === 0)
					{
						return END_ERROR (
							res, 500,
							"Internal error!", error_1
						);
					}

					return END_SUCCESS (
						res, 200,
							JSON.stringify(response)
					);
				}
			);
		});
	});
});

app.post("/auth/v1/token/revoke", function (req, res) {

	const body		= res.locals.body;
	const id		= res.locals.email;

	const tokens		= body.tokens;
	const token_hashes	= body["token-hashes"];

	if (tokens && token_hashes)
	{
		return END_ERROR (
			res, 400,
			"Provide either 'tokens' or 'token-hashes', not both"
		);
	}

	if ( (! tokens) && (! token_hashes))
		return END_ERROR (res, 400, "Provide either 'tokens' or 'token-hashes'");

	let num_tokens_revoked = 0;

	if (tokens)
	{
		// user is a consumer

		if (! (tokens instanceof Array))
			return END_ERROR (res, 400, "Invalid 'tokens' field in body");

		for (const token of tokens)
		{
			if (
				(! is_string_safe(token))		||
				(! token.startsWith(SERVER_NAME + "/"))
			)
			{
				return END_ERROR (
					res, 400, "Invalid token: " + token + ". " +
					String(num_tokens_revoked) + " tokens revoked."
				);
			}

			if ((token.match(/\//g) || []).length !== 2)
				return END_ERROR (res, 400, "Invalid token: " + token);

			const issued_by			= token.split("/")[0];
			const issued_to			= token.split("/")[1];
			const random_part_of_token	= token.split("/")[2];

			if (
				(issued_by 			!== SERVER_NAME)	||
				(issued_to			!== id)			||
				(random_part_of_token.length	!== TOKEN_LENGTH_HEX)
			) {
				return END_ERROR (
					res, 403, "Invalid token: " + token
				);
			}

			const sha256_of_token = crypto.createHash("sha256")
						.update(random_part_of_token)
						.digest("hex");

			const select_rows = select.token.sync (

				"SELECT 1 FROM token "	+
				"WHERE id = $1::text " 	+
				"AND token = $2::text "	+
				"AND expiry > NOW() LIMIT 1",
				[
					id,		// 1
					sha256_of_token	// 2
				]
			);

			if (select_rows.length === 0)
			{
				return END_ERROR (
					res, 400,
					"Invalid token: "			+
						token				+
					". "					+
						String(num_tokens_revoked)	+
					" tokens revoked"
				);
			}

			update.token.sync (

				"UPDATE token SET revoked = true "	+
				"WHERE id = $1::text "			+
				"AND token = $2::text "			+
				"AND expiry > NOW()",
				[
					id,		// 1
					sha256_of_token	// 2
				]
			);

			++num_tokens_revoked;
		}
	}
	else
	{
		// user is a provider

		if (! (token_hashes instanceof Array))
			return END_ERROR (res, 400, "Invalid 'token-hashes' field in body");

		const sha1_id 		= crypto.createHash("sha1")
						.update(id)
						.digest("hex");

		const email_domain	= id.split("@")[1];

		const provider_id_in_db	= sha1_id + "@" + email_domain;

		for (const token_hash of token_hashes)
		{
			// TODO set revoked = true if all providers keys are false ?

			if ((! is_string_safe(token_hash)) || (token_hash.length > MAX_TOKEN_HASH_LENGTH))
			{
				return END_ERROR (
					res, 400,
					"Invalid token-hash: "			+
						token_hash + ". "		+
						String(num_tokens_revoked)	+
					" tokens revoked."
				);
			}

			const select_rows = select.token.sync (

				"SELECT 1 FROM token "			+
				"WHERE token = $1::text "		+
				"AND providers-> $2::text "		+	
				"= 'true' "				+
				"AND expiry > NOW() LIMIT 1",
				[
					token_hash,		// 1
					provider_id_in_db	// 2
				]
			);

			if (select_rows.length === 0)
			{
				return END_ERROR (
					res, 400,
					"Invalid token-hash: "		+
						token_hash + ". "	+
					String(num_tokens_revoked)	+
					" tokens revoked"
				);
			}

			const provider_false = {};
				provider_false[provider_id_in_db] = false;

			update.token.sync (

				"UPDATE token "				+
				"SET providers = "			+
				"providers || $1::jsonb "		+
				"WHERE token = $2::text "		+
				"AND providers-> $3::text = 'true' "	+
				"AND expiry > NOW()",
					[
						JSON.stringify(provider_false),	// 1
						token_hash,			// 2
						provider_id_in_db		// 3
					]
			);

			++num_tokens_revoked;
		}
	}

	return END_SUCCESS (res, 200, SUCCESS);
});

app.post("/auth/v1/token/revoke-all", function (req, res) {

	const body		= res.locals.body;
	const id		= res.locals.email;

	if (! body.serial)
		return END_ERROR (res, 400, "No 'serial' found in the body");

	if (! is_string_safe(body.serial))
		return END_ERROR (res, 400, "invalid 'serial' field");

	if (! body.fingerprint)
	{
		return END_ERROR (
			res, 400,
			"No 'fingerprint' found in the body"
		);
	}

	if (! is_string_safe(body.fingerprint,":")) // fingerprint contain ':' char
		return END_ERROR (res, 400, "invalid 'fingerprint' field");

	const serial 		= body.serial.toLowerCase();
	const fingerprint	= body.fingerprint.toLowerCase();

	const sha1_id 		= crypto.createHash("sha1")
					.update(id)
					.digest("hex");

	const email_domain	= id.split("@")[1];

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	update.token.async (

		"UPDATE token SET revoked = true "	+
		"WHERE id = $1::text "			+
		"AND cert_serial = $2::text "		+
		"AND cert_fingerprint = $3::text "	+
		"AND expiry > NOW() "			+
		"AND revoked = false",
		[
			id,		// 1
			serial,		// 2
			fingerprint	// 3
		],

		(error,results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			const response = {
				success			: true,
				"num-tokens-revoked"	: results.rowCount
			};

			const provider_false = {};
			provider_false[provider_id_in_db] = false;

			update.token.async (

				"UPDATE token "				+
				"SET providers = "			+
				"providers || $1::jsonb "		+
				"WHERE cert_serial = $2::text "		+
				"AND cert_fingerprint = $3::text "	+
				"AND expiry > NOW() "			+
				"AND revoked = false "			+
				"AND providers-> $4::text = 'true' ",

				[
					JSON.stringify(provider_false),	// 1
					serial,				// 2
					fingerprint,			// 3
					provider_id_in_db		// 4
				],

				(error_1, results_1) =>
				{
					if (error_1)
					{
						return END_ERROR (
							res, 500,
							"Internal error!", error_1
						);
					}

					response["num-tokens-revoked"] += results_1.rowCount;
					return END_SUCCESS (
						res, 200,
							JSON.stringify(response)
					);
				}
			);
		}
	);
});

app.post("/auth/v1/acl/set", function (req, res) {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	const policy = body.policy;

	if (typeof policy !== "string")
		return END_ERROR (res, 400, "Invalid policy");

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash("sha1")
					.update(provider_id)
					.digest("hex");

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	const base64policy	= Buffer.from(policy).toString("base64");
	const rules		= policy.split(";");

	let policy_in_json;

	try {
		policy_in_json = rules.map(function (t) {
			return (parser.parse(t));
		});
	}
	catch (x) {
		const err = String(x).replace(/\n/g," ");
		return END_ERROR (res, 400, "Syntax error in policy: " + err);
	}

	select.policy.async (
		"SELECT 1 FROM policy WHERE id = $1::text LIMIT 1",
			[provider_id_in_db], (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		let query;
		let parameters;

		if (results.rows.length > 0)
		{
			query = "UPDATE policy SET policy = $1::text," +
				"policy_in_json = $2::jsonb WHERE id = $3::text";

			parameters = [
				base64policy,			// 1
				JSON.stringify(policy_in_json),	// 2
				provider_id_in_db		// 3
			];

			update.policy.async (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500, "Internal error!", error_1
					);
				}

				return END_SUCCESS (res, 200, SUCCESS);
			});
		}
		else
		{
			query = "INSERT INTO "	+
				"policy VALUES ($1::text, $2::text, $3::jsonb)";

			parameters = [
				provider_id_in_db,		// 1
				base64policy,			// 2
				JSON.stringify(policy_in_json)	// 3
			];

			insert.policy.async (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500, "Internal error!", error_1
					);
				}
	
				return END_SUCCESS (res, 200, SUCCESS);
			});
		}
	});
});

app.post("/auth/v1/acl/append", function (req, res) {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	const policy = body.policy;

	if (typeof policy !== "string")
		return END_ERROR (res, 400, "Invalid policy");

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash("sha1")
					.update(provider_id)
					.digest("hex");

	const provider_id_in_db	= sha1_id + "@" + email_domain;
	const rules		= policy.split(";");

	let policy_in_json;

	try {
		policy_in_json = rules.map(function (t) {
			return (parser.parse(t));
		});
	}
	catch (x) {
		const err = String(x).replace(/\n/g," ");
		return END_ERROR (res, 400, "Syntax error in policy :" + err);
	}

	select.policy.async ("SELECT policy FROM policy WHERE id = $1::text LIMIT 1",
		[provider_id_in_db], (error, results) =>
	{
		if (error)
			return END_ERROR (res,500,"Internal error!",error);

		let query;
		let parameters;

		if (results.rows.length === 1)
		{
			const old_policy	= Buffer.from (
							results.rows[0].policy,
							"base64"
						).toString("ascii");

			const new_policy	= old_policy + ";" + policy;

			const base64policy	= Buffer.from(new_policy)
							.toString("base64");

			const new_rules = new_policy.split(";");

			try {
				policy_in_json = new_rules.map(function (t) {
					return (parser.parse(t));
				});
			}
			catch (x)
			{
				const err = String(x).replace(/\n/g," ");

				return END_ERROR (
					res, 400,
						"Syntax error in policy: " + err
				);
			}

			query = "UPDATE policy SET policy = $1::text," +
				"policy_in_json = $2::jsonb WHERE id = $3::text";

			parameters = [
				base64policy,			// 1
				JSON.stringify(policy_in_json),	// 2
				provider_id_in_db		// 3
			];

			update.policy.async (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500, "Internal error!", error_1
					);
				}

				return END_SUCCESS (res, 200, SUCCESS);
			});
		}
		else
		{
			const base64policy = Buffer
						.from(policy)
						.toString("base64");

			query = "INSERT INTO policy "	+
				"VALUES ($1::text, $2::text, $3::jsonb)";

			parameters = [
				provider_id_in_db,		// 1
				base64policy,			// 2
				JSON.stringify(policy_in_json)	// 3
			];

			insert.policy.async (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500, "Internal error!", error_1
					);
				}

				return END_SUCCESS (res, 200, SUCCESS);
			});
		}
	});
});

app.post("/auth/v1/acl", function (req, res) {

	const provider_id	= res.locals.email;

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash("sha1")
					.update(provider_id)
					.digest("hex");

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	select.policy.async (
		"SELECT policy FROM policy WHERE id = $1::text LIMIT 1",
			[provider_id_in_db], (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (results.rows.length === 0)
			return END_ERROR (res, 400, "No policies set yet!");

		const response = {
			"policy" : Buffer.from(results.rows[0].policy,"base64")
					.toString("ascii")
		};

		return END_SUCCESS (res, 200, JSON.stringify(response));
	});
});

app.post("/auth/v1/audit/tokens", function (req, res) {

	const body		= res.locals.body;
	const id		= res.locals.email;

	if (! body.hours)
		return END_ERROR (res, 400, "No 'hours' found in the body");

	const hours = parseInt (body.hours,10);

	// 5 yrs max
	if (isNaN(hours) || hours < 0 || hours > 43800) {
		return END_ERROR (res, 400, "Invalid 'hours' field");
	}

	const as_consumer = [];
	const as_provider = [];

	select.token.async (

		"SELECT issued_at,expiry,request,cert_serial,"		+
		"cert_fingerprint,introspected,revoked "		+
		"FROM token "						+
		"WHERE id = $1::text "					+
		"AND issued_at >= (NOW() - $2::interval) ",
		"ORDER BY issued_at DESC",
		[
			id,			// 1
			hours + " hours"	// 2
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		for (const row of results.rows)
		{
			as_consumer.push ({
				"token-issued-at"		: row.issued_at,
				"introspected"			: row.introspected,
				"revoked"			: row.revoked,
				"expiry"			: row.expiry,
				"certificate-serial-number"	: row.cert_serial,
				"certificate-fingerprint"	: row.cert_fingerprint,
				"request"			: row.request,
			});
		}

		const sha1_id 		= crypto.createHash("sha1")
						.update(id)
						.digest("hex");

		const email_domain	= id.split("@")[1];
		const provider_id_in_db	= sha1_id + "@" + email_domain;

		select.token.async (

			"SELECT id,token,issued_at,expiry,request,"	+
			"cert_serial,cert_fingerprint,"			+
			"revoked,introspected,"				+
			"providers-> $1::text  "			+
			"AS is_valid_token_for_provider "		+
			"FROM token "					+
			"WHERE providers-> $1::text  "			+
			"IS NOT NULL "					+
			"AND issued_at >= (NOW() - $2::interval) ",
			"ORDER BY issued_at DESC",

			[
				provider_id_in_db,	// 1
				hours + " hours"	// 2
			],

		(error, results) =>
		{

			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			for (const row of results.rows)
			{
				const revoked = (
					row.revoked || (! row.is_valid_token_for_provider)
				);

				as_provider.push ({
					"consumer"			: row.id,
					"token-hash"			: row.token,
					"token-issued-at"		: row.issued_at,
					"introspected"			: row.introspected,
					"revoked"			: revoked,
					"expiry"			: row.expiry,
					"certificate-serial-number"	: row.cert_serial,
					"certificate-fingerprint"	: row.cert_fingerprint,
					"request"			: row.request,
				});
			}

			const response = {
				"as-consumer"	: as_consumer,
				"as-provider"	: as_provider,
			};

			return END_SUCCESS (
				res, 200, JSON.stringify(response)
			);
		});
	});
});

app.post("/auth/v1/group/add", function (req, res) {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	const consumer_id = body.consumer.toLowerCase();

	if (! is_string_safe (consumer_id))
		return END_ERROR (res, 400, "Invalid 'consumer' field");

	if (! body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	const group_name = body.group.toLowerCase();

	if (! is_string_safe (group_name))
		return END_ERROR (res, 400, "Invalid 'group' field");

	if (! body["valid-till"])
		return END_ERROR (res, 400, "No 'valid-till' found in the body");

	const valid_till = parseInt(body["valid-till"],10);

	// 1 year max
	if (isNaN(valid_till) || valid_till < 0 || valid_till > 8760) {
		return END_ERROR (res, 400, "Invalid 'valid-till' field");
	}

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash("sha1")
					.update(provider_id)
					.digest("hex");

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	insert.groups.async (

		"INSERT INTO groups "				+
			"VALUES ($1::text, $2::text, $3::text,"	+
			"NOW() + $4::interval)",
		[
			provider_id_in_db,	// 1
			consumer_id,		// 2
			group_name,		// 3
			valid_till + " hours"	// 4
		],

	(error, results) =>
	{
		if (error || results.rowCount === 0)
			return END_ERROR (res, 500, "Internal error!", error);

		return END_SUCCESS (res, 200, SUCCESS);
	});
});

app.post("/auth/v1/group/list", function (req, res) {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	let group_name = body.group;

	if (group_name)
	{
		group_name = group_name.toLowerCase();

		if (! is_string_safe (group_name))
			return END_ERROR (res, 400, "Invalid 'group' field");
	}

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash("sha1")
					.update(provider_id)
					.digest("hex");

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	const response = [];

	if (group_name)
	{
		select.groups.async (

			"SELECT consumer, valid_till FROM groups "	+
			"WHERE id = $1::text "				+
			"AND group_name = $2::text "			+
			"AND valid_till > NOW()",
			[
				provider_id_in_db,	// 1
				group_name		// 2
			],

		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			for (const row of results.rows)
			{
				response.push ({
					"consumer"	: row.consumer,
					"valid-till"	: row.valid_till
				});
			}

			return END_SUCCESS (res, 200, JSON.stringify(response));
		});
	}
	else
	{
		select.groups.async (

			"SELECT consumer,group_name,valid_till "	+
			"FROM groups "					+
			"WHERE id = $1::text "				+
			"AND valid_till > NOW()",

			[provider_id_in_db],
		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			for (const row of results.rows)
			{
				response.push ({
					"consumer"	: row.consumer,
					"group"		: row.group_name,
					"valid-till"	: row.valid_till
				});
			}

			return END_SUCCESS (res, 200, JSON.stringify(response));
		});
	}
});

app.post("/auth/v1/group/delete", function (req, res) {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	const consumer_id = body.consumer.toLowerCase();

	if (consumer_id !== "*")
	{
		if (! is_string_safe (consumer_id))
			return END_ERROR (res, 400, "Invalid 'consumer' field");
	}

	if (! body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	const group_name = body.group.toLowerCase();

	if (! is_string_safe (group_name))
		return END_ERROR (res, 400, "Invalid 'group' field");

	const email_domain	= provider_id.split("@")[1];

	const sha1_id 		= crypto.createHash("sha1")
					.update(provider_id)
					.digest("hex");

	const provider_id_in_db	= sha1_id + "@" + email_domain;

	let query = 	"UPDATE groups SET "				+
			"valid_till = (NOW() - interval '1 seconds') "	+
			"WHERE id = $1::text "				+
			"AND group_name = $2::text "			+
			"AND valid_till > NOW()";

	const parameters = [
			provider_id_in_db,	// 1
			group_name		// 2
	];

	if (consumer_id !== "*")
	{
		query += " AND consumer = $3::text ";
		parameters.push(consumer_id);	// 3
	}

	update.groups.async (query, parameters, (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (consumer_id !== "*" && results.rowCount === 0)
			return END_ERROR (res, 400, "Consumer not in the group");

		const response = {
			success			: true,
			"num-consumers-deleted"	: results.rowCount
		};

		return END_SUCCESS (res, 200, JSON.stringify(response));
	});
});

app.post("/auth/v1/certificate-info", function (req, res) {

	const response = {
		'id'			: res.locals.email,
		'certificate-class'	: res.locals.cert_class
	};

	return END_SUCCESS (
		res, 200, JSON.stringify(response)
	);
});

app.all("/*", function (req, res) {

	const pathname = url.parse(req.url).pathname;

	if (req.method === "POST")
	{
		console.log("=>>> Invalid API : ",pathname);

		return END_ERROR (
			res, 404,
				"No such API. Please visit: "	+
				"<http://auth.iudx.org.in> for documentation."
		);
	}
	else
	{
		return END_ERROR (
			res, 405,
				"Method must be POST. Please visit: "	+
				"<http://auth.iudx.org.in> for documentation."
		);
	}
});

app.on("error", function(e) {
	console.error(e);
});

/* --- run --- */

if (! is_openbsd)
{
	// ======================== START preload code for chroot =============

	const _tmp = ["x can x x"].map(function (t) {
		return (parser.parse(t));
	});

	evaluator.evaluate(_tmp, {});

	dns.lookup("google.com", {all:true}, (error, address) => {
		if (error)
			log("red","DNS to google.com failed ");
		else
			log("green","google.com = " + JSON.stringify(address));
	});

	// ======================== END preload code for chroot   =============
}

function drop_worker_privileges()
{
	const do_drop_privileges = true; // change this for testing !

	if (! do_drop_privileges)
		return;

	for (const k in password)
		delete password[k];	// forget all passwords

	if (is_openbsd)
	{
		if (EUID === 0)
		{
			process.setgid("_aaa");
			process.setuid("_aaa");
		}

		unveil("/usr/lib",			"r" );
		unveil("/usr/libexec/ld.so",		"r" );
		unveil(__dirname + "/node_modules",	"r" );
		unveil(__dirname + "/node-aperture",	"r" );

		unveil();
	}
	else
	{
		if (EUID === 0)
		{
			process.setgid("_aaa");
			chroot("/home/iudx-auth-server","_aaa");
			process.chdir ("/");
		}
	}

	if (is_openbsd)
		pledge.init ("error stdio tty prot_exec inet rpath dns recvfd");
}

if (cluster.isMaster)
{
	if (is_openbsd)
	{
		unveil("/usr/local/bin/node",	"x");
		unveil("/usr/lib",		"r");
		unveil("/usr/libexec/ld.so",	"r");

		unveil();

		pledge.init (
			"error stdio tty prot_exec inet rpath dns recvfd " +
			"sendfd exec proc"
		);
	}

	log("yellow","Master started with pid : " + process.pid);

	for (let i = 0; i < NUM_CPUS; i++) {
		cluster.fork();
	}

	cluster.on("exit", (worker, unused_var_code, unused_var_signal) => {

		log("red","Worker " + worker.process.pid + " died.");

		cluster.fork();
	});

	if (is_openbsd) // drop "rpath" and "dns"
	{
		pledge.init (
			"error stdio tty prot_exec inet recvfd " +
			"sendfd exec proc"
		);
	}
}
else
{
	https.createServer(https_options,app).listen(443,"0.0.0.0");

	drop_worker_privileges();

	log("green","Worker started with pid " + process.pid);
}

// EOF
