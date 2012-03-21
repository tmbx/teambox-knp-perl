#!/usr/bin/perl

use Test::More tests => 15;
use Teambox::KNP;
require 'config.pl';

$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{source_address}]);
is($r->{ok}, 1, 'successful fetch for ' . $config{source_address});
ok(length($r->{key_array}[0]) > 0, 'presence of returned key data');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{target_address}]);
is($r->{ok}, 1, 'successful fetch for ' . $config{target_address});
ok(length($r->{key_array}[0]) > 0, 'presence of returned key data');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{invalid_address}]);
is($r->{ok}, 1, 'failure of fetch for ' . $config{invalid_address});
ok(length($r->{key_array}[0]) == 0, 'presence returned key data0');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 2,
                               address_array => [$config{source_address},
                                                 $config{target_address}]);
is($r->{ok}, 1, 'successful fetch for 2 addresses');
ok(length($r->{key_array}[0]) > 0, 'presence of key data at 0');
ok(length($r->{key_array}[1]) > 0, 'presence of key data at 1');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{source_ex}]);
is($r->{ok}, 1, 'successful fetch for 1 Exchange address');
ok(length($r->{key_array}[0]) > 0, 'presence of key data at 0');
$knp->close();

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY_BY_ID(key_id => $config{source_mid});
is($r->{ok}, 1, "successful fetch for key ID $config{source_mid}");
is($r->{owner_name}, $config{source_name}, "value of owner name = $config{source_name}");
ok(length($r->{key_data}) > 0, "presence of key data");
ok(length($r->{tm_key_data}) > 0, "presence of timestamping key data");
$knp->close();
