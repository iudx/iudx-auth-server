"use strict";

var auth_server	= "https://auth.iudx.org.in";

var dos		= id("dots");
var code	= id("code");
var time	= id("time");
var button	= id("button");
var request	= id("response");
var response	= id("response");
var jsonViewer	= new JSONViewer();

var error_codes = {
	"0"	: "Authentication failed : <a href=https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSDidNotSucceed>CORS issue</a> [OR] no <a href=https://en.wikipedia.org/wiki/Client_certificate>client-side certificate</a> was provided",
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

document.querySelector("#result").appendChild(jsonViewer.getContainer());

function post(url,body)
{
	var ajax	= new XMLHttpRequest();
	var start_time	= new Date();

	ajax.onreadystatechange = function()
	{
		if (this.readyState === 4)
		{
			time.innerHTML = "<font color=" + color_code[this.status] + ">" + this.status + " - " + error_codes[this.status] + "</font> (took " + (new Date() - start_time)/1000 + " seconds)";

			dots.style.visibility		= "hidden";

			try
			{
				jsonViewer.showJSON(JSON.parse(this.responseText));
			}
			catch
			{
				var error = {
					"error" : {
						"message" : "Authentication failed. No response from server",
					}
				};

				jsonViewer.showJSON(JSON.parse(JSON.stringify(error)));
			}

			response.style.visibility	= "visible"; 

			button.style.visibility		= "visible";
		}
	};

	ajax.open("POST",url,true);
	ajax.withCredentials = true;
	ajax.setRequestHeader("Content-Type", "text/plain");
	ajax.send(body);
}

function id(id)
{
	return document.getElementById(id);
}

function init()
{
	document.querySelector("#result").appendChild(jsonViewer.getContainer());
}

function call(endpoint)
{
	var body = {};
	var e = document.forms[0].elements;

	for (var i = 0; i < e.length; ++i)
	{
		if (e[i].type === "text" || e[i].type === "textarea")
		{
			var k = e[i].name;
			var v = e[i].value;

			if (k && v)
			{
				k = k.trim().replace("_","-");
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
