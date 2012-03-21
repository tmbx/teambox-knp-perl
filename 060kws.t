#!/usr/bin/perl -W

use Data::Dumper;
use Test::More tests => 6;
use Teambox::KNP;
require 'config.pl';

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('failed login') if $r->{ok} != 1;
$r = $knp->KNP_CMD_GET_KWS_TICKET();
is($r->{ok}, 1, 'successful request for KWS ticket');
ok(length($r->{ticket}) > 0, 'presence of ticket data');
$knp->close();

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('failed login') if $r->{ok} != 1;
$r = $knp->KNP_CMD_CONVERT_EXCHANGE(nb_address => 2,
                                    address_array => [$config{source_ex},
                                                      $config{target_ex}]);
is($r->{ok}, 1, 'successful conversion of Exchange address');
ok(scalar($r->{email_array}) != 2, 'two converted addresses');
ok($r->{email_array}[0] =~ /source/, 'has Mister Source address converted');
ok($r->{email_array}[1] =~ /target/, 'has Miss Target address converted');
