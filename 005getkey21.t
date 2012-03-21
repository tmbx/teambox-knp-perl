#!/usr/bin/perl

use Teambox::KNP;
use Test::More tests => 6;
require 'config.pl';

$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
is($r->{ok}, 1, 'successful request');
ok(length($r->{key_data}) > 0, 'presence of key data > 0');
is($r->{owner_name}, $config{source_name}, "value of owner name = $config{source_name}");
$knp->close();

$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{target_mid});
is($r->{ok}, 1, 'successful request');
ok(length($r->{key_data}) > 0, 'presence of key data > 0');
is($r->{owner_name}, $config{target_name}, "value of owner name = $config{target_name}");
$knp->close();
