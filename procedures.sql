CREATE OR REPLACE FUNCTION get_tokens_rate_per_second (in consumer text, out result numeric)
RETURNS numeric AS $$
BEGIN
   SELECT into result COUNT(*)/60.0
   FROM token
   WHERE id= consumer
   AND issued_at >= (NOW() - interval '60 seconds');
END; $$
LANGUAGE plpgsql STABLE STRICT;;


CREATE OR REPLACE FUNCTION get_policy (in provider text, out policy_in_text varchar,out policy_in_json json)
RETURNS record AS $$
BEGIN
   SELECT INTO policy_in_text ,policy_in_json policy,policy_in_json FROM policy 
   WHERE id = provider;
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION get_groups(in provider text, in consumer text, out result varchar)
RETURNS varchar AS $$
BEGIN
   SELECT DISTINCT into group_name group_name 
   FROM groups
   WHERE id = $1::text 
   AND consumer = $2::text 
   AND valid_till > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION get_tokens_per_day(in consumer text, in resource json, out result numeric)
RETURNS numeric AS $$
BEGIN
   SELECT into result COUNT(*) 
   FROM token
   WHERE id= consumer
   AND resource_ids @> resource ::jsonb
   AND DATE_TRUNC('day',issued_at) = DATE_TRUNC('day',NOW());
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION get_existing_token_details(in consumer text, in token text, out result numeric)
RETURNS numeric AS $$
BEGIN
   SELECT into result EXTRACT(EPOCH FROM (expiry - NOW())) AS token_time,request,resource_ids,server_token 
   FROM token 
   WHERE id = consumer AND token = token 
   AND revoked = false AND expiry > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;
 

/*This function not added getting error1*/
CREATE OR REPLACE FUNCTION updateToken_proc(a json, b json, c json, token_time TIMESTAMP,d text, e text)
RETURNS void AS $$
DECLARE token_time numeric = CONCAT('{"',provider_id_in_db, '":false}')::jsonb;
BEGIN
   UPDATE token SET request = a, resource_ids = b , server_token = c, expiry =  CONCAT('NOW() + interval',token_time,'seconds') 
   WHERE 							
   id = d AND 					
   token = e  AND				
   expiry > NOW();
END; $$
LANGUAGE plpgsql VOLATILE STRICT;


/*From here need to update*/
/*Error*/
CREATE OR REPLACE FUNCTION write1_token_proc(a text, b text, c TIMESTAMP, d json, e text,f text ,g json,h boolean,i boolean, j integer, k json, l json)
RETURNS VOID AS $$

BEGIN
  INSERT INTO token VALUES(a, b , NOW(), CONCAT ('interval',c,'seconds'),d , e, f,NOW(),g,h,i,j,k,l); 
END; $$
LANGUAGE plpgsql VOLATILE STRICT;


CREATE OR REPLACE FUNCTION get_token(in token text,  out expiry numeric, out request json, out cert_class integer, out server_token json, out providers json )
RETURNS record  AS $$
BEGIN
   SELECT into expiry, request, cert_class, server_token, providers  expiry,request,cert_class,server_token,providers
   FROM token
   WHERE token = token
   AND revoked = false AND expiry > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION update_token(in token text)
RETURNS VOID AS $$
BEGIN
   UPDATE token SET introspected = true
   WHERE token = token
   AND revoked = false
   AND expiry > NOW();
END; $$
LANGUAGE plpgsql VOLATILE STRICT;


CREATE OR REPLACE FUNCTION select_rows_token1(in id text, in token text, out result numeric)
RETURNS numeric AS $$
BEGIN
   SELECT into result 1 from token 
   WHERE id = id 
   AND token = token
   AND expiry > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION update_token2(in id text, in token text)
RETURNS VOID AS $$
BEGIN
   UPDATE token SET revoked = true WHERE id = id
   AND token = token
   AND expiry > NOW();
END; $$
LANGUAGE plpgsql VOLATILE STRICT;


CREATE OR REPLACE FUNCTION select_rows_token2(in token text, in provider_id_in_db text,out result numeric)
RETURNS numeric AS $$
BEGIN
   SELECT into result 1 from token
   WHERE token = token						
   AND providers-> provider_id_in_db = 'true'
   AND expiry > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION update_token3(in token text, in provider_id_in_db text)
RETURNS VOID AS $$
DECLARE provider_id jsonb = CONCAT('{"',provider_id_in_db, '":false}')::jsonb;
BEGIN
   UPDATE token
   SET providers = providers ||  provider_id
   WHERE token = token
   AND providers-> provider_id_in_db  = 'true'
   AND expiry > NOW();
END; $$
LANGUAGE plpgsql;


/*This gives error as serial & fingerprint doesn't exist in token table
CREATE OR REPLACE FUNCTION update_token_set_proc(a text,b text, c text) 
RETURNS VOID AS $$
BEGIN
   UPDATE token SET revoked = true 
   WHERE id = a 
   AND serial = b
   AND fingerprint = c
   AND expiry > NOW()
   AND revoked = false;
END; $$
LANGUAGE plpgsql;

*/


CREATE OR REPLACE FUNCTION select_policy1(in provider_id text, out result numeric)
RETURNS numeric AS $$
BEGIN
   SELECT into result 1 FROM policy WHERE id = provider_id;
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE OR REPLACE FUNCTION update_policy(in policy_in_text text,in policy_in_json json,in provider_id text)
RETURNS void AS $$
BEGIN
   UPDATE policy SET policy = policy_in_text , policy_in_json = policy_in_json WHERE id = provider_id;
END; $$
LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION insert_policy(in provider_id text, in policy_in_text text,in policy_in_json c json )
RETURNS VOID AS $$
BEGIN
   INSERT INTO policy VALUES (provider_id,policy_in_text,policy_in_json);
END; $$
LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION select_policy2(in provider_id text, out result varchar )
RETURNS varchar AS $$
BEGIN
   SELECT into result policy FROM policy WHERE id = provider_id;
END; $$
LANGUAGE plpgsql STABLE STRICT;     


CREATE OR REPLACE FUNCTION get_token_details(in id text, out issued_at numeric,out expiry numeric , out request json, out cert_serial varchar, out cert_fingerprint varchar, out introspected boolean, out revoked boolean,in hours numeric )
RETURNS record AS $$
BEGIN
   SELECT into issued_at,expiry,request,cert_serial,cert_fingerprint,introspected,revoked issued_at,expiry,request,cert_serial,cert_fingerprint,introspected,revoked 
   FROM token 										
   WHERE id = id									
   AND issued_at >= CONCAT ('NOW()', '-',hours,'hours') ;
END; $$
LANGUAGE plpgsql STABLE STRICT;


      /*ERRRRRR*/
CREATE OR REPLACE FUNCTION select_token_details(out id text, out token text,out issued_at numeric , out expiry TIMESTAMP, out request json, out cert_serial varchar, out fingerprint varchar, out revoked boolean,out introspected boolean,out providers jsonb ,IN provider_id_in_db text,IN hours numeric)
RETURNS record AS $$
DECLARE provider_id_in_db text
BEGIN
   SELECT into id,token,issued_at,expiry,request,cert_serial,fingerprint,revoked,introspected,providers id,token,issued_at,expiry,request,cert_serial,cert_fingerprint,revoked, introspected,providers-> provider_id_in_db  AS has_provider_revoked 
   FROM token
   WHERE providers-> provider_id_in_db  IS NOT NULL 
   AND issued_at >= CONCAT ('NOW()', '-',hours,'hours');
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE or REPLACE FUNCTION add_groups(in provider_id text, in consumer_id text, in group_name text, in valid_till TIMESTAMP)
RETURNS void AS $$
BEGIN
   INSERT INTO groups
   VALUES (provider_id, consumer_id, group_name, CONCAT (NOW(),valid_till,hours ));
END; $$
LANGUAGE plpgsql;


CREATE or REPLACE FUNCTION get_groups_list(in provider_id text, in grp_name text, out consumer text, out valid_till numeric)
RETURNS record AS $$
BEGIN
   SELECT into consumer, valid_till consumer, valid_till FROM groups
   WHERE id = provider_id		
   AND group_name = grp_name
   AND valid_till > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE or REPLACE FUNCTION get_groups_list_details(in provider_id text, out consumer text, out grp_name  text,out valid_till TIMESTAMP)
RETURNS record AS $$
BEGIN
   SELECT into consumer,grp_name,valid_till consumer,group_name,valid_till
   FROM groups
   WHERE id = provider_id				
   AND valid_till > NOW();
END; $$
LANGUAGE plpgsql STABLE STRICT;


CREATE or REPLACE FUNCTION delete_groups(in provider_id text, in grp_name text, out result numeric)
RETURNS numeric AS $$
BEGIN
   DELETE FROM groups
   WHERE id = provider_id
   AND group_name = grp_name
   AND valid_till > NOW();
END; $$
LANGUAGE plpgsql;
