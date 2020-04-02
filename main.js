/* vim: set ts=8 sw=4 tw=0 noet : */

/*
 * Copyright (c) 2020
 *
 * Arun Babu    {barun       <at> iisc <dot> ac <dot> in}
 * Bryan Robert {bryanrobert <at> iisc <dot> ac <dot> in}
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
const dns			= require("dns");
const url			= require("url");
const cors			= require("cors");
const ocsp			= require("ocsp");
const Pool			= require("pg").Pool;
const https			= require("https");
const assert			= require("assert").strict;
const chroot			= require("chroot");
const crypto			= require("crypto");
const logger			= require("node-color-log");
const cluster			= require("cluster");
const express			= require("express");
const timeout			= require("connect-timeout");
const aperture			= require("./node-aperture");
const immutable			= require("immutable");
const geoip_lite		= require("geoip-lite");
const bodyParser		= require("body-parser");
const http_request		= require("request");
const pgNativeClient		= require("pg-native");
const pg			= new pgNativeClient();

const TOKEN_LEN			= 16;
const TOKEN_LEN_HEX		= 2 * TOKEN_LEN;

const EUID			= process.geteuid();
const is_openbsd		= os.type() === "OpenBSD";
const pledge			= is_openbsd ? require("node-pledge")	: null;
const unveil			= is_openbsd ? require("openbsd-unveil"): null;

const NUM_CPUS			= os.cpus().length;
const SERVER_NAME		= "auth.iudx.org.in";

const MAX_TOKEN_TIME		= 31536000; // in seconds (1 year)

const MIN_TOKEN_HASH_LEN	= 64;
const MAX_TOKEN_HASH_LEN	= 64;

const MAX_SAFE_STRING_LEN	= 512;

const MIN_CERT_CLASS_REQUIRED = immutable.Map({

	"/auth/v1/token/introspect"		: 1,
	"/auth/v1/certificate-info"		: 1,

	"/auth/v1/token"			: 2,

	"/marketplace/v1/credit-info"		: 2,
	"/marketplace/v1/credit/topup"		: 2,
	"/marketplace/v1/audit/credit"		: 2,
	"/marketplace/v1/confirm-payment"	: 2,

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

const password	= {
	"DB"	: fs.readFileSync ("passwords/auth.db.password","ascii").trim(),
};

// async postgres connection
const pool = new Pool ({
	host		: DB_SERVER,
	port		: 5432,
	user		: "auth",
	database	: "postgres",
	password	: password.DB,
});

pool.connect();

// sync postgres connection
pg.connectSync (
	"postgresql://auth:"+ password.DB + "@" + DB_SERVER + ":5432/postgres",
		(err) =>
		{
			if(err) {
				throw err;
			}
		}
);

/* --- express --- */

const app = express();

app.disable("x-powered-by");

app.use(timeout("5s"));
app.use(
	cors ({
		credentials	:	true,
		methods		:	["POST"],
		origin		:	(origin, callback) => {
						callback(null, origin ? true : false);
					}
	})
);

app.use(bodyParser.raw({type:"*/*"}));
app.use(security);

/* --- aperture --- */

const apertureOpts = {

	types		: aperture.types,
	typeTable	: {

		ip			: "ip",
		time			: "time",

		tokens_per_day		: "number",	// tokens issued today

		api			: "string",	// the API to be called
		method			: "string",	// the method for API

		"cert.class"		: "number",	// the certificate class
		"cert.cn"		: "string",
		"cert.o"		: "string",
		"cert.ou"		: "string",
		"cert.c"		: "string",
		"cert.st"		: "string",
		"cert.gn"		: "string",
		"cert.sn"		: "string",
		"cert.title"		: "string",

		"cert.issuer.cn"	: "string",
		"cert.issuer.email"	: "string",
		"cert.issuer.o"		: "string",
		"cert.issuer.ou"	: "string",
		"cert.issuer.c"		: "string",
		"cert.issuer.st"	: "string",

		groups			: "string",	// CSV actually

		country			: "string",
		region			: "string",
		timezone		: "string",
		city			: "string",
		latitude		: "number",
		longitude		: "number",
	}
};

const parser	= aperture.createParser		(apertureOpts);
const evaluator	= aperture.createEvaluator	(apertureOpts);

/* --- https --- */

const system_trusted_certs = is_openbsd ?
				"/etc/ssl/cert.pem" :
				"/etc/ssl/certs/ca-certificates.crt";

const trusted_CAs = [
	fs.readFileSync("ca.iudx.org.in.crt"),
	fs.readFileSync("CCAIndia2015.cer"),
	fs.readFileSync("CCAIndia2014.cer"),
	system_trusted_certs
];

const https_options = {
	key			: fs.readFileSync("https-key.pem"),
	cert			: fs.readFileSync("https-certificate.pem"),
	ca			: trusted_CAs,
	requestCert		: true,
	rejectUnauthorized	: true,
};

/* --- functions --- */

function sha1 (string)
{
	return crypto
		.createHash("sha1")
		.update(string)
		.digest("hex");
}

function sha256 (string)
{
	return crypto
		.createHash("sha256")
		.update(string)
		.digest("hex");
}

function base64 (string)
{
	return Buffer
		.from(string)
		.toString("base64");
}

function send_telegram (message)
{
	http_request ( telegram_url + "[ AUTH ] : " + message,
		(error, response, body) =>
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

function log(color, msg)
{
	const message = new Date() + " | " + msg;

	if (color === "red") {
		send_telegram(message);
	}

	logger.color(color).log(message);
}

function END_SUCCESS (res, response = null)
{
	// if no response is given, just send success

	if (! response)
		response = {"success":true};

	res.setHeader("Content-Type", "application/json");

	res.status(200).end(JSON.stringify(response) + "\n");
}

function END_ERROR (res, http_status, msg, exception = null)
{
	if (exception)
		log("red", String(exception).replace(/\n/g," "));

	res.setHeader("Content-Type",	"application/json");
	res.setHeader("Connection",	"close");

	const response = {
		error : msg,
	};

	res.status(http_status).end(JSON.stringify(response) + "\n");

	res.socket.end();
	res.socket.destroy();
}

function is_valid_email (email)
{
	if (! email || typeof email !== "string")
		return false;

	if (email.length < 5 || email.length > 64)
		return false;

	// reject email ids starting with invalid chars
	const invalid_start_chars = ".-_@";

	if (invalid_start_chars.indexOf(email[0]) !== -1)
		return false;

	/*
		Since we use SHA1 (160 bits) for storing email hashes:

			the allowed chars in the email login is -._a-z0-9
			which is : 1 + 1 + 1 + 26 + 10 = ~40 possible chars

			in the worst case of brute force attacks with 31 chars is
				40**31 > 2**160

			but for 30 chars it is
				40**30 < 2**160

			and since we have a good margin for 30 chars
				(2**160) - (40**30) > 2**157

			hence, as a precaution, limit the login length to 30.

		SHA1 has other attacks though, maybe we should switch to better
		hash algorithm in future.
	*/

	const split = email.split("@");

	if (split.length !== 2)
		return false;

	const user = split[0]; // the login

	if (user.length === 0 || user.length > 30)
		return false;

	let num_dots = 0;

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
				case "@":
					break;

				case ".":
					++num_dots;
					break;

				default:
					return false;
			}
		}
	}

	if (num_dots < 1)
		return false;

	return true;
}

function is_certificate_ok (req, cert, validate_email)
{
	if ((! cert) || (! cert.subject))
		return "No subject found in the certificate";

	if (! cert.subject.CN)
		return "No CN found in the certificate";

	if (validate_email)
	{
		if (! is_valid_email(cert.subject.emailAddress))
			return "Invalid emailAddress field in the certificate";

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
				// TODO
				// As this could be a fraud commited by a sub-CA
				// maybe revoke the sub-CA certificate

				log ("red",
					"Invalid certificate: issuer = "+
						issuer_domain		+
					" and issued to = "		+
						cert.subject.emailAddress
				);

				return "Invalid certificate issuer";
			}
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

		res.header("Referrer-Policy",			"no-referrer-when-downgrade");
		res.header("X-Frame-Options",			"deny");
		res.header("X-XSS-Protection",			"1; mode=block");
		res.header("X-Content-Type-Options",		"nosniff");

		res.header("Access-Control-Allow-Origin",	req.headers.origin);
		res.header("Access-Control-Allow-Methods",	"POST");
	}

	const error = is_certificate_ok (req,cert,validate_email);

	if (error !== "OK")
		return "Invalid certificate : " + error;

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

	if (cert_issuer.startsWith("iudx.sub.ca@"))
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
				issuer.fingerprint = issuer
							.fingerprint
							.replace(/:/g,"")
							.toLowerCase();

				issuer.serialNumber = issuer
							.serialNumber
							.toLowerCase();

				for (const c of CRL)
				{
					if (c.issuer === "ca@iudx.org.in")
					{
						const serial = c.serial
								.toLowerCase()
								.replace(/^0+/,"");

						const fingerprint = c.fingerprint
									.replace(/:/g,"")
									.toLowerCase();

						if (serial === issuer.serial && fingerprint === issuer.fingerprint)
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

	if (str.length === 0 || str.length > MAX_SAFE_STRING_LEN)
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

	const email = cert
			.issuer
			.emailAddress
			.toLowerCase();

	// certificate issuer should be IUDX CA or a IUDX sub-CA

	return (email ==="ca@iudx.org.in" || email.startsWith("iudx.sub.ca@"));
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

/* --- basic security checks to be done at every API call --- */

function security (req, res, next)
{
	if (! has_started_serving_apis)
	{
		if (is_openbsd) // drop "rpath"
			pledge.init("error stdio tty prot_exec inet dns recvfd");

		has_started_serving_apis = true;
	}

	const api			= url.parse(req.url).pathname;
	const min_class_required	= MIN_CERT_CLASS_REQUIRED.get(api);

	if (! min_class_required)
	{
		return END_ERROR (
			res, 404,
				"No such API. Please visit : "	+
				"<http://auth.iudx.org.in> for documentation."
		);
	}

	const cert		= req.socket.getPeerCertificate(true);

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

		const error = is_secure(req,res,cert,true); // validate emails

		if (error !== "OK")
			return END_ERROR (res, 403, error);

		pool.query("SELECT crl FROM crl LIMIT 1", [], (error,results) =>
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
		});
	}
	else
	{
		ocsp.check(
			{cert:cert.raw, issuer:cert.issuerCertificate.raw},
		(err, ocsp_response) =>
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

			// Certificates issued by other CAs
			// may not have an "emailAddress" field.
			// By default consider them as a class-1 certificate

			const error = is_secure(req,res,cert,false);

			if (error !== "OK")
				return END_ERROR (res, 403, error);

			res.locals.cert_class	= 1;
			res.locals.email	= "";

			// but if the certificate has a valid "emailAddress"
			// field then we consider it as a class-2 certificate

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
					"A class-" + min_class_required	+
					" or above certificate is"	+
					" required to call this API"
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
		});
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

/* --- Auth APIs --- */

app.post("/auth/v1/token", (req, res) => {

	const cert				= res.locals.cert;
	const cert_class			= res.locals.cert_class;
	const body				= res.locals.body;
	const consumer_id			= res.locals.email;

	const resource_id_dict			= {};
	const resource_server_token		= {};
	const sha256_of_resource_server_token	= {};

	const request_array			= object_to_array(body.request);
	const processed_request_array		= [];

	if ((! request_array) || (request_array.length < 1))
	{
		return END_ERROR (
			res, 400,
				"'request' field must be a valid JSON array " +
				"with at least 1 element"
		);
	}

	const rows = pg.querySync (

		"SELECT COUNT(*)/60.0 "	+
		"AS rate "		+
		"FROM token "		+
		"WHERE id = $1::text "	+
		"AND issued_at >= (NOW() - interval '60 seconds')",
		[
			consumer_id,	// 1
		],
	);

	// in last 1 minute
	const tokens_rate_per_second = parseFloat (rows[0].rate);

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
			"cert.cn"		: cert.subject.CN	|| "",
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

			country			: geo.country		|| "",
			region			: geo.region		|| "",
			timezone		: geo.timezone		|| "",
			city			: geo.city		|| "",
			latitude		: geo.ll[0]		|| 0,
			longitude		: geo.ll[1]		|| 0,
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
		const resource = row.id;

		if (! is_string_safe(resource, "*_")) // allow some chars
		{
			const error_response = {
				"message"	: "id contains unsafe characters",
				"invalid-input"	: resource,
			};

			return END_ERROR (res, 400, error_response);
		}

		if (typeof row.method === "string")
			row.methods = [row.method];

		if (! row.methods)
			row.methods = ["*"];

		if ( ! (row.methods instanceof Array))
		{
			return END_ERROR (res, 400,
				"Invalid 'methods' for resource id : " +
				resource
			);
		}

		if (row.api && typeof row.api === "string")
			row.apis = [row.api];

		if (! row.apis)
			row.apis = ["/*"];

		if (! row.body)
			row.body = null;

		if ( ! (row.apis instanceof Array))
		{
			return END_ERROR (res, 400,
				"Invalid 'apis' for resource id : " +
				resource
			);
		}

		if ((resource.match(/\//g) || []).length < 3)
		{
			return END_ERROR (res, 400,
				"Invalid resource id "		+
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

		const split			= resource.split("/");

		const email_domain		= split[0].toLowerCase();
		const sha1_of_email		= split[1].toLowerCase();

		const provider_id_hash		= email_domain + "/" + sha1_of_email;

		const resource_server		= split[2].toLowerCase();
		const resource_name		= split.slice(3).join("/");

		providers			[provider_id_hash]	= true;

		// to be generated later
		resource_server_token		[resource_server]	= true;

		// to be generated later
		sha256_of_resource_server_token	[resource_server]	= true;

		const rows = pg.querySync (

			"SELECT policy,policy_in_json FROM policy " +
			"WHERE id = $1::text LIMIT 1",
			[
				provider_id_hash,	// 1
			]
		);

		if (rows.length === 0)
		{
			return END_ERROR (res, 400,
				"Invalid resource id; no policy found for : " +
					resource
			);
		}

		const policy_in_text = Buffer.from (
						rows[0].policy, "base64"
					)
					.toString("ascii")
					.toLowerCase();

		const policy_in_json	= rows[0].policy_in_json;

		// full name of resource eg: bangalore.domain.com/streetlight-1
		context.resource = resource_server + "/" + resource_name;

		context.conditions.groups = "";

		if (policy_in_text.search(" consumer-in-group") > 0)
		{
			const rows = pg.querySync (

				"SELECT DISTINCT group_name "	+
				"FROM groups "			+
				"WHERE id = $1::text "		+
				"AND consumer = $2::text "	+
				"AND valid_till > NOW()",
				[
					provider_id_hash,	// 1
					consumer_id		// 2
				]
			);

			const group_array = [];
			for (const g of rows)
				group_array.push(g.group_name);

			context.conditions.groups = group_array.join();
		}

		context.conditions.tokens_per_day = 0;

		if (policy_in_text.search(" tokens_per_day ") > 0)
		{
			const resource_true = {};
				resource_true [resource] = true;

			const rows = pg.querySync (

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
				rows[0].count, 10
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
					res, 400, "Invalid 'api' : " + api
				);
			}

			CTX.conditions.api = api;

			for (const method of row.methods)
			{
				if (typeof method !== "string")
				{
					return END_ERROR (res, 400,
						"Invalid 'method' : " + method
					);
				}

				CTX.conditions.method = method;

				try
				{
					// token expiry time as specified by
					// the provider in the policy

					const result = evaluator.evaluate (
						policy_in_json,
						CTX
					);

					const token_time_in_policy	= result.expiry;
					const payment_amount		= result.amount;
					// const payment_currency	= result.currency;

					if ((! token_time_in_policy) || token_time_in_policy < 0 || payment_amount < 0)
					{
						const error_response = {
							"message"	: "unauthorized",
							"invalid-input"	: {
								"id"		: resource,
								"api"		: api,
								"method"	: method
							}
						};

						return END_ERROR (res, 403, error_response);
					}

					const cost_per_second		= payment_amount / token_time_in_policy;

					total_data_cost_per_second	+= cost_per_second;

					if (! payment_info[provider_id_hash])
						payment_info[provider_id_hash] = 0.0;

					payment_info[provider_id_hash]	+= cost_per_second;

					token_time = Math.min (
						token_time,
						token_time_in_policy
					);
				}
				catch (x)
				{
					const error_response = {
						"message"	: "unauthorized",
						"invalid-input"	: {
							"id"		: resource,
							"api"		: api,
							"method"	: method
						}
					};

					return END_ERROR (res, 403, error_response);
				}
			}
		}

		if (requested_token_time)
			token_time = Math.min(requested_token_time,token_time);

		processed_request_array.push ({
			"id"		: resource,
			"methods"	: row.methods,
			"apis"		: row.apis,
			"body"		: row.body,
		});

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

		const split		= existing_token.split("/");

		const issued_by		= split[0];
		const issued_to		= split[1];
		const random_hex	= split[2];

		if (
			(issued_by		!== SERVER_NAME)	||
			(issued_to		!== consumer_id)	||
			(random_hex.length	!== TOKEN_LEN_HEX)
		) {
			return END_ERROR (res, 403, "Invalid existing-token");
		}

		const sha256_of_existing_token	= sha256(existing_token);

		existing_row = pg.querySync (

			"SELECT EXTRACT(EPOCH FROM (expiry - NOW())) "	+
			"AS token_time,request,resource_ids,"		+
			"server_token "					+
			"FROM token WHERE "				+
			"id = $1::text AND "				+
			"token = $2::text AND "				+
			"revoked = false AND "				+
			"expiry > NOW() LIMIT 1",
			[
				consumer_id,				// 1
				sha256_of_existing_token,		// 2
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

		token = existing_token; // as given by the user
	}
	else
	{
		const random_hex = crypto
					.randomBytes(TOKEN_LEN)
					.toString("hex");

		/* Token format = issued-by / issued-to / random-hex-string */

		token = SERVER_NAME + "/" + consumer_id + "/" + random_hex;
	}

	const response = {

		"token"		: token,
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
		{
			return END_ERROR (
				res, 402,
					"Not enough balance in credits : " +
					total_payment_amount
			);
		}

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
			/* server-token format = issued-to / random-hex-string */

			resource_server_token[key] = key + "/" +
							crypto
							.randomBytes(TOKEN_LEN)
							.toString("hex");

			sha256_of_resource_server_token[key] = sha256 (
				resource_server_token[key]
			);
		}
	}

	response["server-token"]	= resource_server_token;
	const sha256_of_token		= sha256(token);

	let query;
	let parameters;

	if (existing_token)
	{
		// merge both existing values

		const old_request	= existing_row[0].request;
		const new_request	= old_request.concat(processed_request_array);

		const new_resource_ids_dict = Object.assign(
			{}, existing_row[0].resource_ids, resource_id_dict
		);

		query = "UPDATE token SET "				+
				"request = $1::jsonb,"			+
				"resource_ids = $2::jsonb,"		+
				"server_token = $3::jsonb,"		+
				"expiry = NOW() + $4::interval "	+
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

		pool.query (query, parameters, (error,results) =>
		{
			if (error || results.rowCount === 0)
			{
				return END_ERROR (
					res, 500,
					"Internal error!", error
				);
			}

			return END_SUCCESS (res,response);
		});
	}
	else
	{
		query = "INSERT INTO token VALUES("			+
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
			JSON.stringify(processed_request_array),	// 4
			cert.serialNumber,				// 5
			cert.fingerprint,				// 6
			JSON.stringify(resource_id_dict),		// 7
			cert_class,					// 8
			JSON.stringify(sha256_of_resource_server_token),// 9
			JSON.stringify(providers)			// 10
		];

		pool.query (query, parameters, (error,results) =>
		{
			if (error || results.rowCount === 0)
			{
				return END_ERROR (
					res, 500,
					"Internal error!", error
				);
			}

			return END_SUCCESS (res,response);
		});
	}
});

app.post("/auth/v1/token/introspect", (req, res) => {

	const cert	= res.locals.cert;
	const body	= res.locals.body;

	if ((! cert.subject) || (! is_string_safe(cert.subject.CN)))
		return END_ERROR (res, 400, "Invalid CN in the certificate");

	const resource_server_name_in_cert = cert.subject.CN.toLowerCase();

	if (! body.token)
		return END_ERROR (res, 400, "No 'token' found in the body");

	if ((! is_string_safe(body.token)) || (! body.token.startsWith(SERVER_NAME + "/")))
		return END_ERROR (res, 400, "Invalid 'token' field");

	if ((body.token.match(/\//g) || []).length !== 2)
		return END_ERROR (res, 400, "Invalid 'token' field");

	const token		= body.token.toLowerCase();
	let server_token	= body["server-token"] || true;

	if (server_token === true || server_token === "true")
	{
		server_token = true;
	}
	else
	{
		if (! is_string_safe(server_token))
			return END_ERROR (res, 400, "Invalid 'server-token'");

		if ((server_token.match(/\//g) || []).length !== 1)
			return END_ERROR (res, 400, "Invalid 'server-token'");

		const split		= server_token.split("/");

		const issued_to		= split[0];
		const random_hex	= split[1];

		if (issued_to !== resource_server_name_in_cert)
			return END_ERROR (res, 400, "Invalid 'server-token'");

		if (random_hex.length !== TOKEN_LEN_HEX)
			return END_ERROR (res, 400, "Invalid 'server-token'");
	}

	const consumer_request = body.request;

	if (consumer_request)
	{
		if (! (consumer_request instanceof Array))
		{
			return END_ERROR (
				res, 400,
				"'request' field must be an valid JSON array"
			);
		}
	}

	const split		= token.split("/");

	const issued_by		= split[0];
	const issued_to		= split[1];
	const random_hex	= split[2];

	if (
		(issued_by		!== SERVER_NAME)	||
		(random_hex.length	!== TOKEN_LEN_HEX)	||
		(! is_valid_email(issued_to))
	) {
		return END_ERROR (res, 400, "Invalid token");
	}

	const	ip		= req.connection.remoteAddress;
	let	ip_matched	= false;

	dns.lookup(resource_server_name_in_cert, {all:true},
	(error, ip_addresses) =>
	{
		if (error)
		{
			return END_ERROR (
				res, 400,
				"Invalid hostname : " +
					resource_server_name_in_cert
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
				"Your certificate's hostname in CN and " +
				"your IP does not match!"
			);
		}

		// TODO select payment_required from token table

		const sha256_of_token = sha256(token);

		pool.query (

			"SELECT expiry,request,cert_class,"	+
			"server_token,providers "		+
			"FROM token "				+
			"WHERE id = $1::text "			+
			"AND token = $2::text "			+
			"AND revoked = false "			+
			"AND expiry > NOW() LIMIT 1",
			[
				issued_to,			// 1
				sha256_of_token			// 2
			],

		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

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
						"Invalid 'server-token' field "
					);
				}

				const sha256_of_server_token = sha256(server_token);

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
					const sha256_of_server_token = sha256(server_token);

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
				const split		= r.id.split("/");

				const email_domain	= split[0].toLowerCase();
				const sha1_of_email	= split[1].toLowerCase();

				const provider_id_hash	= email_domain + "/" + sha1_of_email;

				const resource_server	= split[2].toLowerCase();

				// if provider exists
				if (providers[provider_id_hash])
				{
					if (resource_server === resource_server_name_in_cert)
						request_for_resource_server.push (r);
				}
			}

			if (request_for_resource_server.length === 0)
				return END_ERROR (res, 403, "Invalid token");

			if (consumer_request)
			{
				const l1 = Object.keys(
					consumer_request
				).length;

				const l2 = Object.keys(
					request_for_resource_server
				).length;

				// more number of requests than what is allowed

				if (l1 > l2)
				{
					return END_ERROR (
						res, 403, "Unauthorized !"
					);
				}

				for (const r1 of consumer_request)
				{
					if (! (r1 instanceof Object))
					{
						const error_response = {
							"message"	: "invalid request",
							"invalid-input"	: r1,
						};

						return END_ERROR (res, 400,
							error_response
						);
					}

					// default values

					if (! r1.methods)
						r1.methods = ["*"];

					if (! r1.apis)
						r1.apis = ["/*"];

					if (! r1.body)
						r1.body = null;

					const keys1 = Object
							.keys(r1);

					let resource_found = false;

					for (const r2 of request_for_resource_server)
					{
						if (r1.id === r2.id)
						{
							const keys2 = Object
								.keys(r2);

							const total_keys = new Set (
								keys1.concat(keys2)
							);

							for (const k of total_keys)
							{
								if (JSON.stringify(r1[k]) !== JSON.stringify(r2[k]))
								{
									const error_response = {
										"message"	: "unauthorized",
										"invalid-input"	: {
											"id"	: r1.id,
											"key"	: k
										}
									};

									return END_ERROR (res, 403, error_response);
								}
							}

							resource_found = true;
							break;
						}
					}

					if (! resource_found)
					{
						const error_response = {
							"message"	: "unauthorized",
							"invalid-input"	: r1,
						};

						return END_ERROR (res, 403, error_response);
					}
				}
			}

			const response = {
				"consumer"			: issued_to,
				"expiry"			: results.rows[0].expiry,
				"request"			: request_for_resource_server,
				"consumer-certificate-class"	: results.rows[0].cert_class,
			};

			pool.query (

				"UPDATE token SET introspected = true "	+
				"WHERE token = $1::text "		+
				"AND revoked = false "			+
				"AND expiry > NOW()",
				[
					sha256_of_token,		// 1
				],

				(error_1, results_1) =>
				{
					if (error_1 || results_1.rowCount === 0)
					{
						return END_ERROR (
							res, 500,
							"Internal error!",
							error_1
						);
					}

					return END_SUCCESS (res,response);
				}
			);
		});
	});
});

app.post("/auth/v1/token/revoke", (req, res) => {

	const body		= res.locals.body;
	const id		= res.locals.email;

	const tokens		= body.tokens;
	const token_hashes	= body["token-hashes"];

	if (tokens && token_hashes)
	{
		return END_ERROR (
			res, 400,
			"Provide either 'tokens' or 'token-hashes'; not both"
		);
	}

	if ( (! tokens) && (! token_hashes))
	{
		return END_ERROR (
			res, 400,
			"No 'tokens' or 'token-hashes' found"
		);
	}

	let num_tokens_revoked = 0;

	if (tokens)
	{
		// user is a consumer

		if (! (tokens instanceof Array))
			return END_ERROR (res, 400, "Invalid 'tokens' field");

		for (const token of tokens)
		{
			if (
				(! is_string_safe(token))		||
				(! token.startsWith(SERVER_NAME + "/"))	||
				((token.match(/\//g) || []).length !== 2)
			)
			{
				const error_response = {
					"message"		: "invalid token",
					"invalid-input"		: token,
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const split		= token.split("/");

			const issued_by		= split[0];
			const issued_to		= split[1];
			const random_hex	= split[2];

			if (
				(issued_by		!== SERVER_NAME)||
				(issued_to		!== id)		||
				(random_hex.length	!== TOKEN_LEN_HEX)
			) {
				const error_response = {
					"message"		: "invalid token",
					"invalid-input"		: token,
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const sha256_of_token = sha256(token);

			const rows = pg.querySync (

				"SELECT 1 FROM token "		+
				"WHERE id = $1::text "		+
				"AND token = $2::text "		+
				"AND expiry > NOW() LIMIT 1",
				[
					id,			// 1
					sha256_of_token		// 2
				]
			);

			if (rows.length === 0)
			{
				const error_response = {
					"message"		: "invalid token",
					"invalid-input"		: token,
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const update_rows = pg.querySync (

				"UPDATE token SET revoked = true "	+
				"WHERE id = $1::text "			+
				"AND token = $2::text "			+
				"AND revoked = false "			+
				"AND expiry > NOW()",
				[
					id,				// 1
					sha256_of_token			// 2
				]
			);

			num_tokens_revoked += update_rows.length;
		}
	}
	else
	{
		// user is a provider

		if (! (token_hashes instanceof Array))
		{
			return END_ERROR (
				res, 400,
					"Invalid 'token-hashes' field"
			);
		}

		const email_domain	= id.split("@")[1];
		const sha1_of_email	= sha1(id);

		const provider_id_hash	= email_domain + "/" + sha1_of_email;

		for (const token_hash of token_hashes)
		{
			// TODO set revoked = true if all providers keys
			// are false ?

			if (
				(! is_string_safe(token_hash))		||
				(token_hash.length < MIN_TOKEN_HASH_LEN)||
				(token_hash.length > MAX_TOKEN_HASH_LEN)
			)
			{
				const error_response = {
					"message"		: "invalid token-hash",
					"invalid-input"		: token_hash,
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const rows = pg.querySync (

				"SELECT 1 FROM token "		+
				"WHERE token = $1::text "	+
				"AND providers-> $2::text "	+
				"= 'true' "			+
				"AND expiry > NOW() LIMIT 1",
				[
					token_hash,		// 1
					provider_id_hash	// 2
				]
			);

			if (rows.length === 0)
			{
				const error_response = {
					"message"		: "invalid token hash",
					"invalid-input"		: token_hash,
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const provider_false = {};
				provider_false[provider_id_hash] = false;

			const update_rows = pg.querySync (

				"UPDATE token "				+
				"SET providers = "			+
				"providers || $1::jsonb "		+
				"WHERE token = $2::text "		+
				"AND providers-> $3::text = 'true' "	+
				"AND expiry > NOW()",
				[
					JSON.stringify(provider_false),	// 1
					token_hash,			// 2
					provider_id_hash		// 3
				]
			);

			num_tokens_revoked += update_rows.length;
		}
	}

	const response = {
		"num-tokens-revoked" : num_tokens_revoked
	};

	return END_SUCCESS (res, response);
});

app.post("/auth/v1/token/revoke-all", (req, res) => {

	const body		= res.locals.body;
	const id		= res.locals.email;

	if (! body.serial)
		return END_ERROR (res, 400, "No 'serial' found in the body");

	if (! is_string_safe(body.serial))
		return END_ERROR (res, 400, "invalid 'serial' field");

	const serial = body.serial.toLowerCase();

	if (! body.fingerprint)
	{
		return END_ERROR (
			res, 400,
			"No 'fingerprint' found in the body"
		);
	}

	if (! is_string_safe(body.fingerprint,":")) // fingerprint contains ':'
		return END_ERROR (res, 400, "invalid 'fingerprint' field");

	const fingerprint	= body.fingerprint.toLowerCase();

	const email_domain	= id.split("@")[1];
	const sha1_of_email	= sha1(id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"UPDATE token SET revoked = true "	+
		"WHERE id = $1::text "			+
		"AND cert_serial = $2::text "		+
		"AND cert_fingerprint = $3::text "	+
		"AND expiry > NOW() "			+
		"AND revoked = false",
		[
			id,				// 1
			serial,				// 2
			fingerprint			// 3
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
				"num-tokens-revoked" : results.rowCount
			};

			const provider_false = {};
			provider_false[provider_id_hash] = false;

			pool.query (

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
					provider_id_hash		// 4
				],

				(error_1, results_1) =>
				{
					if (error_1)
					{
						return END_ERROR (
							res, 500,
							"Internal error!",
							error_1
						);
					}

					response["num-tokens-revoked"] += results_1.rowCount;

					return END_SUCCESS (res,response);
				}
			);
		}
	);
});

app.post("/auth/v1/acl/set", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	if (typeof body.policy !== "string")
		return END_ERROR (res, 400, "Invalid policy");

	const policy	= body.policy;
	const rules	= policy.split(";");

	let policy_in_json;

	try {
		policy_in_json = rules.map (
			(r) => {
				return (parser.parse(r));
			}
		);
	}
	catch (x) {
		const err = String(x).replace(/\n/g," ");
		return END_ERROR (res, 400, "Syntax error in policy : " + err);
	}

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	const base64policy	= base64(policy);

	pool.query (

		"SELECT 1 FROM policy WHERE id = $1::text LIMIT 1",
		[
			provider_id_hash,	// 1
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		let query;
		let parameters;

		if (results.rows.length > 0)
		{
			query = "UPDATE policy SET policy = $1::text,"	+
				"policy_in_json = $2::jsonb "		+
				"WHERE id = $3::text";

			parameters = [
				base64policy,				// 1
				JSON.stringify(policy_in_json),		// 2
				provider_id_hash			// 3
			];

			pool.query (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500,
							"Internal error!",
							error_1
					);
				}

				return END_SUCCESS (res);
			});
		}
		else
		{
			query = "INSERT INTO "	+
				"policy VALUES ($1::text, $2::text, $3::jsonb)";

			parameters = [
				provider_id_hash,		// 1
				base64policy,			// 2
				JSON.stringify(policy_in_json)	// 3
			];

			pool.query (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500,
							"Internal error!",
							error_1
					);
				}

				return END_SUCCESS (res);
			});
		}
	});
});

app.post("/auth/v1/acl/append", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	if (typeof body.policy !== "string")
		return END_ERROR (res, 400, "Invalid policy");

	const policy	= body.policy;
	const rules	= policy.split(";");

	let policy_in_json;

	try {
		policy_in_json = rules.map (
			(r) => {
				return (parser.parse(r));
			}
		);
	}
	catch (x) {
		const err = String(x).replace(/\n/g," ");
		return END_ERROR (res, 400, "Syntax error in policy : " + err);
	}

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"SELECT policy FROM policy WHERE id = $1::text LIMIT 1",
		[
			provider_id_hash	// 1
		],

	(error, results) =>
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
			const new_rules		= new_policy.split(";");

			try {
				policy_in_json = new_rules.map (
					(r) => {
						return (parser.parse(r));
					}
				);
			}
			catch (x)
			{
				const err = String(x).replace(/\n/g," ");

				return END_ERROR (
					res, 400,
					"Syntax error in policy : " + err
				);
			}

			const base64policy = Buffer
						.from(new_policy)
						.toString("base64");

			query = "UPDATE policy SET policy = $1::text,"	+
				"policy_in_json = $2::jsonb "		+
				"WHERE id = $3::text";

			parameters = [
				base64policy,				// 1
				JSON.stringify(policy_in_json),		// 2
				provider_id_hash			// 3
			];

			pool.query (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500,
							"Internal error!",
							error_1
					);
				}

				return END_SUCCESS (res);
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
				provider_id_hash,		// 1
				base64policy,			// 2
				JSON.stringify(policy_in_json)	// 3
			];

			pool.query (query, parameters, (error_1, results_1) =>
			{
				if (error_1 || results_1.rowCount === 0)
				{
					return END_ERROR (
						res, 500,
							"Internal error!",
							error_1
					);
				}

				return END_SUCCESS (res);
			});
		}
	});
});

app.post("/auth/v1/acl", (req, res) => {

	const provider_id	= res.locals.email;

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"SELECT policy FROM policy WHERE id = $1::text LIMIT 1",
		[
			provider_id_hash	// 1
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (results.rows.length === 0)
			return END_ERROR (res, 400, "No policies set yet!");

		const response = {
			"policy" : Buffer
					.from(results.rows[0].policy,"base64")
					.toString("ascii")
		};

		return END_SUCCESS (res,response);
	});
});

app.post("/auth/v1/audit/tokens", (req, res) => {

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

	pool.query (

		"SELECT issued_at,expiry,request,cert_serial,"	+
		"cert_fingerprint,introspected,revoked,"	+
		"expiry < NOW() as expired "			+
		"FROM token "					+
		"WHERE id = $1::text "				+
		"AND issued_at >= (NOW() - $2::interval) "	+
		"ORDER BY issued_at DESC",
		[
			id,					// 1
			hours + " hours"			// 2
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
				"expired"			: row.expired,
				"certificate-serial-number"	: row.cert_serial,
				"certificate-fingerprint"	: row.cert_fingerprint,
				"request"			: row.request,
			});
		}

		const email_domain	= id.split("@")[1];
		const sha1_of_email	= sha1(id);

		const provider_id_hash	= email_domain + "/" + sha1_of_email;

		pool.query (

			"SELECT id,token,issued_at,expiry,request,"	+
			"cert_serial,cert_fingerprint,"			+
			"revoked,introspected,"				+
			"providers-> $1::text "				+
			"AS is_valid_token_for_provider,"		+
			"expiry < NOW() as expired "			+
			"FROM token "					+
			"WHERE providers-> $1::text "			+
			"IS NOT NULL "					+
			"AND issued_at >= (NOW() - $2::interval) "	+
			"ORDER BY issued_at DESC",
			[
				provider_id_hash,			// 1
				hours + " hours"			// 2
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
					"expired"			: row.expired,
					"certificate-serial-number"	: row.cert_serial,
					"certificate-fingerprint"	: row.cert_fingerprint,
					"request"			: row.request,
				});
			}

			const response = {
				"as-consumer"	: as_consumer,
				"as-provider"	: as_provider,
			};

			return END_SUCCESS (res,response);
		});
	});
});

app.post("/auth/v1/group/add", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	if (! is_string_safe (body.consumer))
		return END_ERROR (res, 400, "Invalid 'consumer' field");

	const consumer_id = body.consumer.toLowerCase();

	if (! body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	if (! is_string_safe (body.group))
		return END_ERROR (res, 400, "Invalid 'group' field");

	const group = body.group.toLowerCase();

	if (! body["valid-till"])
		return END_ERROR (res, 400, "Invalid 'valid-till' field");

	const valid_till = parseInt(body["valid-till"],10);

	// 1 year max
	if (isNaN(valid_till) || valid_till < 0 || valid_till > 8760) {
		return END_ERROR (res, 400, "Invalid 'valid-till' field");
	}

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"INSERT INTO groups "			+
		"VALUES ($1::text, $2::text, $3::text,"	+
		"NOW() + $4::interval)",
		[
			provider_id_hash,		// 1
			consumer_id,			// 2
			group,				// 3
			valid_till + " hours"		// 4
		],

	(error, results) =>
	{
		if (error || results.rowCount === 0)
			return END_ERROR (res, 500, "Internal error!", error);

		return END_SUCCESS (res);
	});
});

app.post("/auth/v1/group/list", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (body.group)
	{
		if (! is_string_safe (body.group))
			return END_ERROR (res, 400, "Invalid 'group' field");
	}

	const group		= body.group ? body.group.toLowerCase() : null;

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	const response = [];

	if (group)
	{
		pool.query (

			"SELECT consumer, valid_till FROM groups "	+
			"WHERE id = $1::text "				+
			"AND group_name = $2::text "			+
			"AND valid_till > NOW()",
			[
				provider_id_hash,			// 1
				group					// 2
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

			return END_SUCCESS (res,response);
		});
	}
	else
	{
		pool.query (

			"SELECT consumer,group_name,valid_till "+
			"FROM groups "				+
			"WHERE id = $1::text "			+
			"AND valid_till > NOW()",
			[
				provider_id_hash		// 1
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
					"group"		: row.group_name,
					"valid-till"	: row.valid_till
				});
			}

			return END_SUCCESS (res,response);
		});
	}
});

app.post("/auth/v1/group/delete", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	if (body.consumer !== "*")
	{
		if (! is_string_safe (body.consumer))
			return END_ERROR (res, 400, "Invalid 'consumer' field");
	}

	const consumer_id = body.consumer ? body.consumer.toLowerCase() : null;

	if (! body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	if (! is_string_safe (body.group))
		return END_ERROR (res, 400, "Invalid 'group' field");

	const group		= body.group.toLowerCase();

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	let query =	"UPDATE groups SET "				+
			"valid_till = (NOW() - interval '1 seconds') "	+
			"WHERE id = $1::text "				+
			"AND group_name = $2::text "			+
			"AND valid_till > NOW()";

	const parameters = [
			provider_id_hash,	// 1
			group			// 2
	];

	if (consumer_id !== "*")
	{
		query += " AND consumer = $3::text ";
		parameters.push(consumer_id);	// 3
	}

	pool.query (query, parameters, (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (consumer_id !== "*" && results.rowCount === 0)
		{
			return END_ERROR (
				res, 400, "Consumer not found in the group"
			);
		}

		const response = {
			"num-consumers-deleted"	: results.rowCount
		};

		return END_SUCCESS (res,response);
	});
});

/* --- Marketplace APIs --- */

app.post("/marketplace/v1/payment/confirm", (req, res) => {
	// TODO
});

app.post("/marketplace/v1/credit/info", (req, res) => {

	// TODO

	// if class 2 - only related to this certificate's public key
	// if class 3 or above - for all ids with this emailAddress

	// select amount from credits table
});

app.post("/marketplace/v1/credit/topup", (req, res) => {

	// TODO

	// if class 2 - only related to this certificate's public key
	// if class 3 or above - for all ids with this emailAddress

	// insert or update amount in credit table
});

app.post("/auth/v1/certificate-info", (req, res) => {

	const cert	= res.locals.cert;

	const response	= {
		"id"			: res.locals.email,
		"certificate-class"	: res.locals.cert_class,
		"serial"		: cert.serialNumber.toLowerCase(),
		"fingerprint"		: cert.fingerprint.toLowerCase(),
	};

	return END_SUCCESS (res,response);
});

/* --- Invalid requests --- */

app.all("/*", (req, res) => {

	if (req.method === "POST")
	{
		return END_ERROR (
			res, 404,
				"No such API. Please visit : "	+
				"<http://auth.iudx.org.in> for documentation."
		);
	}
	else
	{
		return END_ERROR (
			res, 405,
				"Method must be POST. Please visit : "	+
				"<http://auth.iudx.org.in> for documentation."
		);
	}
});

app.on("error", (unused_var_error) => {

});

/* --- The main application --- */

if (! is_openbsd)
{
	// ======================== START preload code for chroot =============

	const _tmp = ["x can y z"].map (
		(r) => {
			return (parser.parse(r));
		}
	);

	evaluator.evaluate(_tmp, {});

	dns.lookup("google.com", {all:true}, (error, address) => {
		if (error)
			log("red","DNS to google.com failed ");
		else
			log("green","google.com = " + JSON.stringify(address));
	});

	// ======================== END preload code for chroot ===============
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

	assert (has_started_serving_apis === false);
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
