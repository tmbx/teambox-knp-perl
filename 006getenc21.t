#!/usr/bin/perl

use Test::More tests => 11;
use Teambox::KNP;
require 'config.pl';

$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{source_address}]);
is($r->{ok}, 1, 'successful fetch for ' . $config{source_address});
ok(length($r->{key_array}[0]) > 0, 'presence of returned key data');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{target_address}]);
is($r->{ok}, 1, 'successful fetch for ' . $config{target_address});
ok(length($r->{key_array}[0]) > 0, 'presence of returned key data');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{invalid_address}]);
is($r->{ok}, 1, 'failure of fetch for ' . $config{invalid_address});
ok(length($r->{key_array}[0]) == 0, 'presence returned key data0');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 2,
                               address_array => [$config{source_address},
                                                 $config{target_address}]);
is($r->{ok}, 1, 'successful fetch for 2 addresses');
ok(length($r->{key_array}[0]) > 0, 'presence of key data at 0');
ok(length($r->{key_array}[1]) > 0, 'presence of key data at 1');
$knp->close();

$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{source_ex}]);
is($r->{ok}, 1, 'successful fetch for 1 Exchange address');
ok(length($r->{key_array}[0]) > 0, 'presence of key data at 0');
$knp->close();
