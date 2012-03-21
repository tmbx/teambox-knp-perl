#!/usr/bin/perl -W

use Data::Dumper;
use Test::More tests => 4;
use Teambox::KNP;
require 'config.pl';

#
# Simple encryption/decryption with password.
#

$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{target_address}]);
$key_data = $r->{key_array}[0];
$knp->close();

my %pkg_cmd = (pkg_type => 3,
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
               pod_addr  => '',
               license_lim => 10,
               license_max => 10,
               license_kdn => "test.kdn");

# First, encrypt something for the target.
$knp = KNP::new($config{kps_host}, $config{kps_port}, 3, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_LIC(%pkg_cmd);
is($r->{ok}, 1, 'password encryption');
ok(length($r->{pkg_output}) > 0, 'presence of encryption output');
$signature = $knp->get_signature_text($r->{pkg_output});
ok(length($signature) > 0, 'extraction of signature data');
$knp->close();
