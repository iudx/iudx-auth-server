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

    PRIMARY KEY (id, token)
);

CREATE UNIQUE INDEX idx_token_id ON public.token(id,token,issued_at);

CREATE TABLE public.credit (
	id			character varying		NOT NULL,
	cert_serial		character varying		NOT NULL,
	cert_fingerprint	character varying		NOT NULL,
	amount			numeric				NOT NULL DEFAULT 0 CHECK (amount >= 0),
	last_updated		timestamp without time zone	NOT NULL,

	CONSTRAINT "credit_pkey" PRIMARY KEY (id, cert_serial, cert_fingerprint)
);

CREATE TABLE public.topup_transaction (
	id			character varying		NOT NULL,
	cert_serial		character varying		NOT NULL,
	cert_fingerprint	character varying		NOT NULL,
	amount			numeric				NOT NULL,
	time			timestamp without time zone	NOT NULL,
	invoice_number		character varying		NOT NULL,
	paid			boolean				NOT NULL,
	payment_details		jsonb				NOT NULL
);

CREATE UNIQUE INDEX idx_topup_transaction ON public.topup_transaction (id,time);

--
-- Functions
--

CREATE OR REPLACE FUNCTION public.update_credit (IN in_invoice_number character varying, IN in_payment_details jsonb)
RETURNS boolean AS
$$
	DECLARE
		my_id			character varying;
		my_cert_serial		character varying;
		my_cert_fingerprint	character varying;
		my_time			timestamp without time zone;
		my_amount		numeric;
		my_num_rows_affected	numeric;
	BEGIN
		UPDATE public.topup_transaction
			SET
				paid		= true,
				time		= NOW(),
				payment_details	= in_payment_details
			WHERE
				invoice_number	= in_invoice_number
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

		GET DIAGNOSTICS my_num_rows_affected = ROW_COUNT;

		IF my_num_rows_affected != 1
		THEN
			ROLLBACK;
			RETURN FALSE;
		END IF;

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
		;

		GET DIAGNOSTICS my_num_rows_affected = ROW_COUNT;

		IF my_num_rows_affected != 1
		THEN
			UPDATE public.credit
				SET
					amount			= amount + my_amount,
					last_updated		= my_time
				WHERE
					id			= my_id
				AND
					cert_serial		= my_cert_serial
				AND
					cert_fingerprint	= my_cert_fingerprint
			;

			GET DIAGNOSTICS my_num_rows_affected = ROW_COUNT;

			IF my_num_rows_affected != 1
			THEN
				ROLLBACK;
				RETURN FALSE;
			END IF;

		END IF;

		COMMIT;
		RETURN TRUE;
	END;
$$
LANGUAGE PLPGSQL STRICT;

--
-- ACCESS CONTROLS
--

ALTER TABLE public.policy		OWNER TO postgres;
ALTER TABLE public.groups		OWNER TO postgres;
ALTER TABLE public.crl			OWNER TO postgres;
ALTER TABLE public.token		OWNER TO postgres;
ALTER TABLE public.credit		OWNER TO postgres;
ALTER TABLE public.topup_transaction	OWNER TO postgres;

ALTER FUNCTION public.update_credit	OWNER TO postgres;

CREATE USER auth		with PASSWORD 'XXX_auth';
CREATE USER update_crl		with PASSWORD 'XXX_update_crl';

GRANT SELECT			ON TABLE public.crl				TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.token				TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.groups				TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.policy				TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.credit				TO auth;
GRANT SELECT,INSERT,UPDATE	ON TABLE public.topup_transaction		TO auth;

GRANT UPDATE			ON TABLE public.crl				TO update_crl;

GRANT EXECUTE ON FUNCTION	public.update_credit(character varying,jsonb)	TO auth;

