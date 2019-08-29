#base_url="https://10.156.14.149/auth/v1"
base_url="https://auth.iudx.org.in/auth/v1"
count=0

echo "Executing APIs using curl -k commands"

provider_crt=$1
provider_key=$2
consumer_crt=$3
consumer_key=$4

#Enter the APIs here

curl -vk -POST --cert $provider_crt --key $provider_key $base_url/acl -d 'policy=all can access * if tokens_per_day < 10' -H "Content-Type: application/x-www-form-urlencoded"

echo ""


curl -k -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"9cf2c2382cf661fc20a4776345a3be7a143a109c@rbccps.org/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["GET"], "body" : {"key":"some-key"} }' -H "Content-Type: application/json"

curl -k -POST --cert $consumer_crt --key $consumer_key  $base_url/token -d '{"resource-id":"9cf2c2382cf661fc20a4776345a3be7a143a109c@rbccps.org/challenge-response.com/resource-xyz", "api": "/latest", "methods": ["GET"], "body" : {"key":"some-key"} }' -H "Content-Type: application/json"

