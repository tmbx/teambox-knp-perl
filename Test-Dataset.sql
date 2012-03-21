--
-- PostgreSQL database cluster dump
--

\connect "template1"

\connect login_db

--
-- PostgreSQL database dump
--

SET client_encoding = 'UNICODE';
SET check_function_bodies = false;

SET SESSION AUTHORIZATION 'postgres';

SET search_path = public, pg_catalog;

--
-- Data for TOC entry 2 (OID 19393)
-- Name: user_login; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY user_login (user_name, passwd, prof_id, status) FROM stdin;
source	source	1	A
target	target	2	A
fdgonthier	fdgonthier	3	A
birtz	birtz	4	A
\.

\connect privkeys_db

--
-- PostgreSQL database dump
--

SET client_encoding = 'UNICODE';
SET check_function_bodies = false;

SET SESSION AUTHORIZATION 'postgres';

SET search_path = public, pg_catalog;

--
-- Data for TOC entry 2 (OID 19402)
-- Name: private_key; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY private_key (key_id, owner_name) FROM stdin;
10	Mister Source
11	Miss Target
2023030	Ataboy
\.


--
-- Data for TOC entry 3 (OID 19406)
-- Name: sig_key; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY sig_key (key_id, key_data) FROM stdin;
10	
11	
\.


--
-- Data for TOC entry 4 (OID 19417)
-- Name: enc_key; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY enc_key (key_id, key_data) FROM stdin;
10	
11	
2023030	
\.


\connect profiles_db

--
-- PostgreSQL database dump
--

SET client_encoding = 'UNICODE';
SET check_function_bodies = false;

SET SESSION AUTHORIZATION 'postgres';

SET search_path = public, pg_catalog;

--
-- Data for TOC entry 9 (OID 19449)
-- Name: organization; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY organization (org_id, name) FROM stdin;
1	Targets
2	Sources
3	Teambox
\.


--
-- Data for TOC entry 10 (OID 19454)
-- Name: profiles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY profiles (prof_id, key_id, org_id, prof_type, user_id, group_id) FROM stdin;
1	10	2	U	1	\N
2	11	1	U	2	\N
3	10	3	U	3	\N
4	10	3	U	4	\N
\.


--
-- Data for TOC entry 11 (OID 19468)
-- Name: user_profiles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY user_profiles (user_id, first_name, last_name, status, prof_id) FROM stdin;
2	Miss	Target	A	2
1	Mister	Source	A	1
3	F.-D.	Gonthier	A	3
4	Laurent	Birtz	A	4
\.


--
-- Data for TOC entry 12 (OID 19477)
-- Name: group_profiles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY group_profiles (group_id, group_name, status, prof_id) FROM stdin;
\.


--
-- Data for TOC entry 13 (OID 19486)
-- Name: email_parts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY email_parts (email_part_id, email_part, group_id) FROM stdin;
\.

--
-- Data for TOC entry 14 (OID 19497)
-- Name: emails; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY emails (email_id, user_id, email_address, status, is_primary) FROM stdin;
6	1	source@source.com	A	t
7	1	source@test.teambox.co	A	f
1	2	target@target.com	A	t
8	2	target@test.teambox.co	A	f
2	3	test@teambox.co	A	f
3	4	test2@teambox.co	A	t
4	4	test@necropolis.teambox.co	A	f
\.

--
-- TOC entry 3 (OID 27234)
-- Name: org_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('org_id_seq', 1, false);


--
-- TOC entry 4 (OID 27236)
-- Name: prof_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('prof_id_seq', 1, false);


--
-- TOC entry 5 (OID 27238)
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('user_id_seq', 1, false);


--
-- TOC entry 6 (OID 27240)
-- Name: group_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('group_id_seq', 1, false);


--
-- TOC entry 7 (OID 27242)
-- Name: email_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('email_id_seq', 1, false);


--
-- TOC entry 8 (OID 27244)
-- Name: email_part_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('email_part_id_seq', 1, false);


\connect pubkeys_db

--
-- PostgreSQL database dump
--

SET client_encoding = 'UNICODE';
SET check_function_bodies = false;

SET SESSION AUTHORIZATION 'postgres';

SET search_path = public, pg_catalog;

--
-- Data for TOC entry 3 (OID 19530)
-- Name: public_key; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public_key (key_id, status, owner_name) FROM stdin;
10	A	Mister Source
11	A	Miss Target
\.


--
-- Data for TOC entry 4 (OID 19534)
-- Name: sig_key; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY sig_key (key_id, key_data) FROM stdin;
10	
11	
\.


--
-- Data for TOC entry 5 (OID 19542)
-- Name: enc_key; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY enc_key (key_id, key_data) FROM stdin;
10	
11	
\.


--
-- Data for TOC entry 6 (OID 27249)
-- Name: pub_fetch_count; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY pub_fetch_count (key_id, fetch_count, fetch_last_date) FROM stdin;
\.


--
-- TOC entry 2 (OID 19528)
-- Name: email_match_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('email_match_seq', 1, false);


\connect template1

--
-- PostgreSQL database dump
--

SET client_encoding = 'UNICODE';
SET check_function_bodies = false;

