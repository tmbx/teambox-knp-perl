#!/usr/bin/perl

use Teambox::KNP;
use Test::More tests => 4;
require 'config.pl';

$knp = KNP::new($config{kps_host}, $config{kps_port});

$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
is($r->{major}, 3, 'major version');
is($r->{minor}, 1, 'minor version');
$knp->close();

$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => 'blarg',
                              password => 'blorg',
                              is_password => 1);
ok($r->{ok} == 0, 'failed login');
$knp->close();

