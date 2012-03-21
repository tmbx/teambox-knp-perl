#!/usr/bin/perl -W

use Data::Dumper;
use Test::More tests => 13;
use Teambox::KNP;
require 'config.pl';

# #
# # Fetch the timestamping key data for the source address.
# #

# First, encrypt something for the target.
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 0,
                                recipient_array => [],
                                nb_pwd    => 1,
                                pwd_array => [{pwd => $config{target_password},
                                               otut => ''}],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'successful password encryption');
ok(length($r->{pkg_output}) > 0, 'presence of encryption output');
$signature = $knp->get_signature_text($r->{pkg_output});
ok(length($signature) > 0, 'extraction of signature data');
$knp->close();

$knp = KNP::new($config{iks_host}, $config{iks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
is($r->{ok}, 1, 'successful signature key fetch');
ok(length($r->{key_data}) > 0, 'presence of key data');
$key_data = $r->{key_data};
$knp->close();

$knp = KNP::new($config{ous_host}, $config{ous_port}, 2, 1);
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 1, 'successful password decryption');
ok(length($r->{sym_key_data}) > 0, 'presence of symmetric key data');
ok(length($r->{otut}) == 0, 'absence of OTUT string');
$knp->close();

#
# Encryption with KNP 2.1, decryption with 3.1
#

$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 0,
                                recipient_array => [],
                                nb_pwd    => 1,
                                pwd_array => [{pwd => $config{target_password},
                                               otut => ''}],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'password encryption (2.1 -> 3.1)');
$knp->close();

$key_data = undef;

# Fetch the timestamping key data for the source address.
$knp = KNP::new($config{iks_host}, $config{iks_port}, 3, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$key_data = $r->{key_data};
$knp->close();

$knp = KNP::new($config{ous_host}, $config{ous_port}, 3, 1);
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               pub_key_data => $key_data,
                               tm_key_data => $tm_key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => '');
is($r->{ok}, 1, 'password decryption (2.1 -> 3.1)');
$knp->close();

#
# Encryption with 3.1, decryption with 2.1
#

$knp = KNP::new($config{kps_host}, $config{kps_port}, 3, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 0,
                                recipient_array => [],
                                nb_pwd    => 1,
                                pwd_array => [{pwd => $config{target_password},
                                               otut => ''}],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'password encryption (3.1 -> 2.1)');
$signature = $knp->get_signature_text($r->{pkg_output});
$knp->close();

# Fetch the timestamping key data for the source address.
$knp = KNP::new($config{iks_host}, $config{iks_port}, 2, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$key_data = $r->{key_data};
$knp->close();

$knp = KNP::new($config{ous_host}, $config{ous_port}, 2, 1);
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => '');
is($r->{ok}, 1, 'password decryption (3.1 -> 2.1)');
$knp->close();
