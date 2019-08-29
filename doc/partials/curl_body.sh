#base_url="https://10.156.14.149/auth/v1"
base_url="https://auth.iudx.org.in/auth/v1"
count=0

echo "Executing APIs using curl -k commands"

#Enter the APIs here

curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key $base_url/acl -d 'policy=all can access * for 2 hours if tokens_per_day < 10' -H "Content-Type: application/x-www-form-urlencoded"

echo ""


curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["GET"], "body" : {"key":"some-key"} }' -H "Content-Type: application/json" 

curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["GET"], "body" : {"key":"some-key"} }' -H "Content-Type: application/json" 

#exit

curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key $base_url/acl -d 'policy=jishnup@rbccps.org can access challenge-response.com/resource-xyz if body.key = "some-key" and api = "/latest" and method = "GET"; jishnup@rbccps.org can access google.com/resource-xyz if country in ("IN") and api = "/latest" and method = "GET"' -H "Content-Type: application/x-www-form-urlencoded"

echo \
"This API is used by <code>PROVIDERS</code> to set ACL policies for <code>CONSUMERS</code>.<br><br> \
In this example, there are two policies created by <b>arun.babu@rbccps.org</b> as a <code>PROVIDER</code> <br> \
<ul>
<li>In the first policy, <a>arun.babu@rbccps.org</a> is granting <i>GET</i> access to  <a>jishnup@rbccps.org</a> for API '<b>/latest</b>' on resource <b>'resource-xyz'</b> hosted on resource-server '<b>challenge-response.com</b>' if request body contains <b>key</b> with value <b>\"some-key\"</b></li>
<li>In the second policy, <a>arun.babu@rbccps.org</a> is granting <i>GET</i> access to <a>jishnup@rbccps.org</a> for API '<b>/latest</b>' on resource <b>'resource-xyz'</b> hosted on resource-server '<b>google.com</b>' if <b>source</b> of request is <b>IN</b> (India)</li>
</ul>" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -GET --cert $provider_crt --key $provider_key $base_url/acl

echo "This API is used by <code>PROVIDERS</code> to get ACL policies set by him/her for <code>CONSUMERS</code>.<br><br> In this example,  <b>arun.babu@rbccps.org</b> as a <code>PROVIDER</code> is requesting to get the list of ACL policies set by him" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["GET"], "body" : {"key":"some-key"} }' -H "Content-Type: application/json" > result

echo \
"This API is used by <code>CONSUMERS</code> to request access to APIs provided by <code>PROVIDERS</code>.<br><br> \
In this example, there are two policies created by <b>arun.babu@rbccps.org</b> as a <code>PROVIDER</code> <br> \
<ul>
<li>In the first policy, <a>arun.babu@rbccps.org</a> is granting <i>GET</i> access to  <a>jishnup@rbccps.org</a> for API '<b>/latest</b>' on resource <b>'resource-xyz'</b> hosted on resource-server '<b>challenge-response.com</b>' if request body contains <b>key</b> with value <b>\"some-key\"</b></li>
<li>In the second policy, <a>arun.babu@rbccps.org</a> is granting <i>GET</i> access to <a>jishnup@rbccps.org</a> for API '<b>/latest</b>' on resource <b>'resource-xyz'</b> hosted on resource-server '<b>google.com</b>' if <b>source</b> of request is <b>IN</b> (India)</li>
</ul>" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["GET"], "body" : {"keyx":"some-key-x", "key": "some-key"} }' -H "Content-Type: application/json" 

echo "API description to be written" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"challenge-response.com/resource-xyz", "provider":"arun.babu@rbccps.org", "api": "/latest", "methods": ["GET"], "body" : {"keyx":"some-key-x", "key": "some-key"} }' -H "Content-Type: application/json" 

echo "API description to be written" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/google.com/resource-xyz", "api": "/latest", "methods": ["GET"] }' -H "Content-Type: application/json" > result_

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"invalid-sha-1@example.com/resource", "api": "/some-api-endpoint", "methods": ["GET"] }' -H "Content-Type: application/json"

echo "API description to be written" > traces/$((count)).trace.info



token=`cat result | cut -f4 -d\"`
token2=`cat result_ | cut -f4 -d\"`



curl -k --trace traces/$((++count)).trace -POST --cert $rs_crt --key $rs_key  $base_url/introspect -H "token:$token" -d ''

echo "API description to be written" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert cert/google.com.pem --key $rs_key  $base_url/introspect -H "token:$token2" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $rs_crt --key $rs_key  $base_url/introspect -H "token":"invalid-token" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/revoke -H "token:$token" -d '' 

echo "API description to be written" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/revoke -H "token:$token" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/revoke -H "token:invalid-token" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/audit/tokens -H "hours:5" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/add-consumer -H "group:confidential" -H "consumer:jishnup@rbccps.org" -H "valid-till:5" -d ''

echo "API description to be written" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/add-consumer -H "group:confidential" -H "consumer:arun.babu@rbccps.org" -H "valid-till:5" -d ''

echo "API description to be written" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -GET --cert $provider_crt --key $provider_key  $base_url/group/list -H "group:confidential"

echo "API description to be written" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/delete-consumer  -H "group:confidential" -H "consumer:arun.babu@rbccps.org" -d ''

echo "API description to be written" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/delete-consumer  -H "group:some-group" -H "consumer:jishnup@rbccps.org" -d ''

echo "API description to be written" > traces/$((count)).trace.info



curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/acl -d 'policy=jishnup@rbccps.org can access * if  method = "POST"; anyone can access challenge-response.com/resource-xyz if consumer-in-group("confidential") and api = "/latest" and method = "POST"' -H "Content-Type: application/x-www-form-urlencoded"

echo "This API is used by <code>PROVIDERS</code> to set ACL policies for <code>CONSUMERS</code>.<br><br> \
	  In this example,  there are two policies.
	  In policy-1, <b>jishnup@rbccps.org</b> as a <code>PROVIDER</code> is granting access to himself for  to \
	  for API '<b>/latest</b>' on resource <b>'resource-xyz'</b> hosted on resource-server '<b>challenge-response.com</b>' if he is a member of <b>confidential</b> group" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/challenge-response.com/resource-xyz", "api": "/some-api-endpoint", "methods": ["POST"] }' -H "Content-Type: application/json"

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/delete-consumer  -H "group:confidential" -H "consumer:jishnup@rbccps.org" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"rbccps.org/9cf2c2382cf661fc20a4776345a3be7a143a109c/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["POST"] }' -H "Content-Type: application/json"

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/delete  -H "group: confidential" -d ''

echo "API description to be written" > traces/$((count)).trace.info


curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/group/delete  -H "group: some-group" -d ''

echo "API description to be written" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -POST --cert $provider_crt --key $provider_key  $base_url/append-acl -d 'policy=jishnup@rbccps.org can access challenge-response.com/resource-xyz if country = "IN"' -H "Content-Type: application/x-www-form-urlencoded"

echo "API description to be written" > traces/$((count)).trace.info

curl -k --trace traces/$((++count)).trace -GET --cert $provider_crt --key $provider_key $base_url/acl

echo "This API is used by <code>PROVIDERS</code> to get ACL policies set by him/her for <code>CONSUMERS</code>.<br><br> In this example,  <b>arun.babu@rbccps.org</b> as a <code>PROVIDER</code> is requesting to get the list of ACL policies set by him" > traces/$((count)).trace.info

