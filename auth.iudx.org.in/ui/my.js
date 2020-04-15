"use strict";

var auth_server	= "https://auth.iudx.org.in";

var dots;
var code;
var time;
var button;
var request;
var response;

var jsonViewer	= new JSONViewer();

var init_done	= false;

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

var error_codes = {
	"0"	: "Authentication failed : No valid <a href=https://en.wikipedia.org/wiki/Client_certificate>client-side certificate</a> was provided [OR] a <a href=https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSDidNotSucceed>CORS</a> issue",
	"200"	: "OK",
	"400"	: "Bad request",
	"401"	: "Unauthorized",
	"402"	: "Payment required",
	"403"	: "Forbidden",
	"500"	: "Internal error",
};

var color_code = {
	"0"	: "red",
	"200"	: "blue",
	"400"	: "red",
	"401"	: "red",
	"402"	: "red",
	"403"	: "red",
	"500"	: "red",
}

function post(url,body)
{
	var ajax	= new XMLHttpRequest();
	var start_time	= new Date();

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
				var error_response = {
					"error" : {
					}
				};
				
				if (this.status === 0)
					error_response.error.message = "Authentication failure";
				else
					error_response.error.message = "Unknown failure!";

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

	var body = {};
	var e = document.forms[0].elements;

	for (var i = 0; i < e.length; ++i)
	{
		if (e[i].type === "text" || e[i].type === "textarea")
		{
			var k = e[i].name;
			var v = e[i].value;

			v = v.trim();

			// if it looks like a JSON do not process it
			if (v.startsWith("[") || v.startsWith("{"))
			{
				var string_v = String(v);

				try
				{
					v = JSON.parse(v);
				}
				catch
				{
					v = string_v;
				}
			}
			else
				v = v.replace(/\n/g,";");

			if (k && v)
			{
				k = k.trim().replace("_","-");

				if (v.trim)
					v = v.trim();

				body[k] = v;
			}
		}
	}

	body = JSON.stringify(body);

	dots.style.visibility		= "visible";

	response.style.visibility	= "hidden";
	button.style.visibility		= "hidden";

	post(auth_server + "/auth/v1/" + endpoint,body);
}
