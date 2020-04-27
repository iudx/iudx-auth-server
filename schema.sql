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
    crl	jsonb	DEFAULT '[]'::jsonb	NOT NULL
);

INSERT INTO public.crl VALUES('[]'::jsonb);


--
-- Name: groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.groups (

    id		character varying		NOT NULL,
    consumer	character varying		NOT NULL,
    group_name	character varying		NOT NULL,
    valid_till	timestamp without time zone	NOT NULL

);

CREATE INDEX idx_groups_id ON public.groups(id,group_name,valid_till);

--
-- Name: policy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.policy (

    id			character varying		PRIMARY KEY,
    policy		character varying(3145728)	NOT NULL,
    policy_in_json	jsonb				NOT NULL,
    previous_policy	character varying(3145728),
    last_updated	timestamp without time zone	NOT NULL

);

CREATE UNIQUE INDEX idx_policy_id ON public.policy(id);

--
-- Name: token; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.token (

    id			character varying		NOT NULL,
    token		character varying		NOT NULL,
    expiry		timestamp without time zone	NOT NULL,
    request		jsonb				NOT NULL,
    cert_serial		character varying		NOT NULL,
    cert_fingerprint	character varying		NOT NULL,
    issued_at		timestamp without time zone	NOT NULL,
    resource_ids	jsonb				NOT NULL,
    introspected	boolean				NOT NULL,
    revoked		boolean				NOT NULL,
    cert_class		integer				NOT NULL,
    server_token	jsonb				NOT NULL,
    providers		jsonb				NOT NULL,
    geoip		jsonb				NOT NULL,

    PRIMARY KEY (id,token)
);

CREATE UNIQUE INDEX idx_token_id ON public.token(id,token,issued_at);

CREATE TABLE public.credit (
	id			character varying		NOT NULL,
	cert_serial		character varying		NOT NULL,
	cert_fingerprint	character varying		NOT NULL,
	amount			numeric				NOT NULL DEFAULT 0 CHECK (amount >= 0),
	last_updated		timestamp without time zone	NOT NULL
);

CREATE TABLE public.topup_transaction (
	id			character varying		NOT NULL,
	cert_serial		character varying		NOT NULL,
	cert_fingerprint	character varying		NOT NULL,
	amount			numeric				NOT NULL,
	time			timestamp without time zone	NOT NULL,
	invoice_number		character varying		NOT NULL,
	paid			boolean				NOT NULL
);

--
-- Procedures
--

CREATE OR REPLACE PROCEDURE public.credit_update (my_invoice_number character varying)
LANGUAGE plpgsql
AS $$
DECLARE
	my_id			character varying;
	my_cert_serial		character varying;
	my_cert_fingerprint	character varying;
	my_time			timestamp without time zone;
	my_amount		numeric;
BEGIN
	UPDATE public.transaction
		SET
			paid = true,
			time = NOW()
		WHERE 
			invoice_number = my_invoice_number
		AND
			paid = false
	RETURNING
		id,
		cert_serial,
		cert_fingerprint,
		time,
		amount

	INTO STRICT
		my_id,
		my_cert_serial,
		my_cert_fingerprint,
		my_time,
		my_amount
	;

	INSERT INTO public.credit (
			id,
			cert_serial,
			cert_fingerprint,
			amount,
			last_updated
		) 

		VALUES (
			my_id,
			my_cert_serial,
			my_cert_fingerprint,
			my_amount,
			my_time
		)
	
	ON CONFLICT (id, cert_serial, cert_fingerprint)
		DO UPDATE
			SET
				amount		= credit.amount + EXCLUDED.amount,
				last_updated	= my_time;
END;
$$;

--
-- ACCESS CONTROLS
--

ALTER TABLE public.policy		OWNER TO postgres;
ALTER TABLE public.groups		OWNER TO postgres;
ALTER TABLE public.crl			OWNER TO postgres;
ALTER TABLE public.token		OWNER TO postgres;
ALTER TABLE public.credit		OWNER TO postgres;
ALTER TABLE public.topup_transaction	OWNER TO postgres;

ALTER PROCEDURE public.credit_update	OWNER TO postgres;

CREATE USER auth		with PASSWORD 'XXX_auth';
CREATE USER update_crl		with PASSWORD 'XXX_update_crl';

GRANT SELECT			ON TABLE public.crl			TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.token			TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.groups			TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.policy			TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.credit			TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.topup_transaction	TO auth;

GRANT UPDATE			ON TABLE public.crl			TO update_crl;

GRANT EXECUTE ON PROCEDURE	public.credit_update(character varying)	TO auth;

