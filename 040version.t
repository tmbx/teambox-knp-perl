#!/usr/bin/perl

use Test::More tests => 2;
use Teambox::KNP;
require 'config.pl';

# That version will be too new.
$knp = KNP::new($config{kps_host}, $config{kps_port}, 99, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 0, 'unsuccessful login');
ok($r->{upgrade} eq 'kps', 'got told to upgrade KPS');
$knp->close();

# We have no deprecated version here yet so we can't really test.
