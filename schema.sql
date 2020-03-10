--
-- PostgreSQL database dump
--

-- Dumped from database version 11.2
-- Dumped by pg_dump version 11.2

SET TIMEZONE='Asia/Kolkata';

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'SQL_ASCII';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: crl; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.crl (
    crl jsonb DEFAULT '[]'::jsonb NOT NULL
);

INSERT INTO public.crl VALUES('[]'::jsonb);

ALTER TABLE public.crl OWNER TO postgres;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.groups (
    id character varying NOT NULL,
    consumer character varying NOT NULL,
    group_name character varying NOT NULL,
    valid_till timestamp without time zone NOT NULL
);

CREATE INDEX idx_groups_id ON public.groups(id,group_name);

ALTER TABLE public.groups OWNER TO postgres;

--
-- Name: policy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.policy (
    id character varying PRIMARY KEY,
    policy character varying(3145728),
    policy_in_json json NOT NULL
);

CREATE UNIQUE INDEX idx_policy_id ON public.policy(id);

ALTER TABLE public.policy OWNER TO postgres;

--
-- Name: token; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.token (
    id character varying NOT NULL,
    token character varying NOT NULL,
    expiry timestamp without time zone NOT NULL,
    request json NOT NULL,
    cert_serial character varying NOT NULL,
    cert_fingerprint character varying NOT NULL,
    issued_at timestamp without time zone NOT NULL,
    resource_ids jsonb NOT NULL,
    introspected boolean NOT NULL,
    revoked boolean NOT NULL,
    cert_class integer NOT NULL,
    server_token jsonb NOT NULL,
    providers jsonb NOT NULL,
    PRIMARY KEY(id, token)
);

CREATE UNIQUE INDEX idx_token_id ON public.token(id,token);

ALTER TABLE public.token OWNER TO postgres;

--
-- ACCESS CONTROLS 
--

CREATE USER auth with PASSWORD 'XXXauth';

GRANT SELECT ON TABLE public.crl TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE public.token TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE public.groups TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE public.policy TO auth;

-- CREATE USER select_crl with PASSWORD 'XXXselect_crl';
CREATE USER update_crl with PASSWORD 'XXXupdate_crl';

-- CREATE USER select_token with PASSWORD 'XXXselect_token';
-- CREATE USER insert_token with PASSWORD 'XXXinsert_token';
-- CREATE USER update_token with PASSWORD 'XXXupdate_token';

-- CREATE USER select_policy with PASSWORD 'XXXselect_policy';
-- CREATE USER insert_policy with PASSWORD 'XXXinsert_policy';
-- CREATE USER update_policy with PASSWORD 'XXXupdate_policy';

-- CREATE USER select_groups with PASSWORD 'XXXselect_groups';
-- CREATE USER insert_groups with PASSWORD 'XXXinsert_groups';
-- CREATE USER update_groups with PASSWORD 'XXXupdate_groups';

-- GRANT SELECT ON TABLE public.crl TO select_crl;
GRANT UPDATE ON TABLE public.crl TO update_crl;

-- GRANT SELECT ON TABLE public.token TO select_token;
-- GRANT INSERT ON TABLE public.token TO insert_token;
-- GRANT UPDATE ON TABLE public.token TO update_token;

-- GRANT SELECT ON TABLE public.groups TO select_groups;
-- GRANT INSERT ON TABLE public.groups TO insert_groups;
-- GRANT UPDATE ON TABLE public.groups TO update_groups;

-- GRANT SELECT ON TABLE public.policy TO select_policy;
-- GRANT INSERT ON TABLE public.policy TO insert_policy;
-- GRANT UPDATE ON TABLE public.policy TO update_policy;

--
-- PostgreSQL database dump complete
--
