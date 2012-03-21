#!/usr/bin/perl

# Test for key and password encryption.

use Test::More tests => 14;
use Teambox::KNP;
require 'config.pl';

#
# Fetch the target key.
#
$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{source_address}]);
is($r->{ok}, 1, 'result of fetch for ' . $config{source_address});
ok(length($r->{key_array}[0]) > 0, 'returned key data');
$key_data = $r->{key_array}[0];
$knp->close();

#
# Encrypt a message with the key.
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'result of login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{source_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => $key_data}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'result of packaging');
ok(length($r->{pkg_output}) > 0, 'length of result text');
ok(length($r->{ksn}) > 0, 'presence of KSN');
ok(length($r->{sym_key}) > 0, 'presence of symmetric key');
$knp->close();

#
# Fetch the target key (Exchange address).
#
$knp = KNP::new($config{eks_host}, $config{eks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{target_address}]);
is($r->{ok}, 1, 'result of fetch for ' . $config{target_address});
ok(length($r->{key_array}[0]) > 0, 'length of returned key data');
$key_data = $r->{key_array}[0];
$knp->close();

#
# Encrypt a message with the key (Exchange address).
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'result of login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{target_address},
                                cc_field  => '',
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => $key_data}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'result of packaging (Exchange address)');
ok(length($r->{pkg_output}) > 0, 'presence of result text');
ok(length($r->{ksn}) > 0, 'presence of KSN');
ok(length($r->{sym_key}) > 0, 'presence of symmetric key');
$knp->close();

