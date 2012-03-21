#!/usr/bin/perl

use Teambox::KNP;
use Test::More tests => 7;
require 'config.pl';

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);

$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'successful login');

$r = $knp->KNP_CMD_GET_USER_INFO();
is($r->{ok}, 1, 'successful info request');
is($r->{mid}, $config{source_mid}, "returned member ID $config{source_mid}");
ok(length($r->{domain_array}) > 0, 'list of returned domains > 0');
is($r->{kpg_is_used}, 1, "presence of KPG data");
ok(length($r->{kpg_address}) > 0, 'length of KPG address > 0');
ok($r->{kpg_port} != 0, "presence of KPG port");

$knp->close();
