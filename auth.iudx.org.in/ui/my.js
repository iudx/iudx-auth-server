"use strict";

const auth_server = "https://auth.iudx.org.in";

let dots;
let code;
let time;
let button;
let request;
let response;

let jsonViewer	= new JSONViewer();

let init_done	= false;

function init ()
{
	if (init_done)
		return;

	dots		= id("dots");
	code		= id("code");
	time		= id("time");
	button		= id("button");
	request		= id("request");
	response	= id("response");

	document.querySelector("#result").appendChild(jsonViewer.getContainer());

	init_done	= true;
}

const error_codes = {
	"0"	: "Authentication failed : No valid <a href=https://en.wikipedia.org/wiki/Client_certificate>client-side certificate</a> was provided [OR] a <a href=https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSDidNotSucceed>CORS</a> issue",
	"200"	: "OK",
	"400"	: "Bad request",
	"401"	: "Unauthorized",
	"402"	: "Payment required",
	"403"	: "Forbidden",
	"500"	: "Internal error",
};

const color_code = {
	"0"	: "red",
	"200"	: "blue",
	"400"	: "red",
	"401"	: "red",
	"402"	: "red",
	"403"	: "red",
	"500"	: "red",
};

function post(url,body)
{
	const	ajax		= new XMLHttpRequest();
	let	start_time	= new Date();

	ajax.onreadystatechange = function()
	{
		if (this.readyState === 4)
		{
			time.innerHTML = ": <font color=" + color_code[this.status] + ">" + this.status + " - " + error_codes[this.status] + "</font> (took " + (new Date() - start_time)/1000 + " seconds)";

			try
			{
				jsonViewer.showJSON(JSON.parse(this.responseText));
			}
			catch
			{
				const error_response = {
					"error" : {
					}
				};
				
				if (this.status === 0)
					error_response.error.message = "Authentication failure";
				else
					error_response.error.message = "Response from the server was not a valid JSON";

				jsonViewer.showJSON(JSON.parse(JSON.stringify(error_response)));
			}

			dots.style.visibility		= "hidden";
			response.style.visibility	= "visible"; 
			button.style.visibility		= "visible";
		}
	};

	ajax.open("POST",url,true);
	ajax.withCredentials = true;
	ajax.setRequestHeader("Content-Type", "text/plain");
	ajax.send(body);

	start_time = new Date();
}

function id(id)
{
	return document.getElementById(id);
}

function call(endpoint)
{
	init();

	const body	= {};
	const e		= document.forms[0].elements;

	for (let i = 0; i < e.length; ++i)
	{
		if (e[i].type === "text" || e[i].type === "textarea")
		{
			let key		= e[i].name;
			let value	= e[i].value;

			value = value.trim();

			// if it looks like a JSON do not process it
			if (value.startsWith("[") || value.startsWith("{"))
			{
				try
				{
					value = JSON.parse(value);
				}
				catch
				{
					value = String(value); 
				}
			}
			else
			{
				if (value.charAt(0) === '"' && value.charAt(value.length - 1) === '"')
				{
    					value = value.substr(1, value.length -2);
				}

				value = value.replace(/\n/g,";");
			}

			if (key && value)
			{
				key = key.trim().replace("_","-");

				if (value.trim)
					value = value.trim();

				body[key] = value;
			}
		}
	}

	const json_body = JSON.stringify(body);

	dots.style.visibility		= "visible";

	response.style.visibility	= "hidden";
	button.style.visibility		= "hidden";

	post(auth_server + "/auth/v1/" + endpoint, json_body);
}
