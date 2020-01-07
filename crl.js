/* vim: set ts=8 sw=4 tw=0 noet : */

/*eslint camelcase: ["error", {properties: "never"}]*/

"use strict";

const fs		= require("fs");
const os		= require("os");
const logger		= require("node-color-log");
const request		= require("sync-request");
const pgNativeClient 	= require("pg-native");
const pg		= new pgNativeClient();

const db_password	= fs.readFileSync ("crl.db.password","ascii").trim();

const is_openbsd	= os.type() === "OpenBSD";
const EUID		= process.geteuid();
const pledge 		= is_openbsd ? require("node-pledge")		: null;
const unveil		= is_openbsd ? require("openbsd-unveil")	: null;

pg.connectSync (
	"postgresql://crl:"+ db_password+ "@127.0.0.1:5432/postgres",
	function(err) {
		if(err)
			throw err;
	}
);

let crl = [];

function log(color, msg)
{
	const message = new Date() + " | " + msg;

	logger.color(color).log(message);
}

function update_crl (body)
{
	let new_crl;

	try
	{
		new_crl = JSON.parse(body);
	}
	catch (x)
	{
		const err = String(x).replace(/\n/g," ");
		log("red","CA did not return a valid JSON : " + err);
		return;
	}

	let updated = false;

	if (new_crl.length !== crl.length)
	{
		updated = true;
	}
	else
	{
		// compare both

		for (let i = 0; i < crl.length; ++i)
		{
			for (const key in crl[i])
			{
				if (crl[i][key] !== new_crl[i][key])
				{
					updated = true;
					break;
				}
			}

			if (updated)
				break;
		}
	}

	if (updated)
	{
		const results = pg.querySync (
			"UPDATE crl SET crl = $1",
				[JSON.stringify(new_crl)]
		);

		if (results.rowCount === 0)
			log("red","CRL update failed!");
		else
		{
			crl = new_crl;
			log("yellow","CRL updated!");
		}
	}
	else
	{
		log("green","CRL is the same");	
	}
}

if (EUID === 0)
{
	process.setgid("nogroup");
	process.setuid("nobody");
}

if (is_openbsd)
{
	unveil("/usr/local/bin/node",	"x");
	unveil("/usr/bin/nc",		"x");
	unveil("/usr/lib",		"r");
	unveil("/usr/libexec/ld.so",	"r");

	pledge.init ("stdio tty prot_exec rpath inet recvfd exec proc");
}

function run()
{
	const res = request("GET","https://ca.iudx.org.in/crl");
	update_crl(res.getBody());   
} 

run();
setInterval(run,3600000);
