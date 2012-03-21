#!/usr/bin/perl

use Data::Dumper;
use Test::More tests => 24;
use Teambox::KNP;
require 'config.pl';

#
# Fetch the timestamping key data for the source address.
#
$knp = KNP::new($config{iks_host}, $config{iks_port});
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$knp->close();

$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);

is($r->{ok}, 1, 'successful login');
BAIL_OUT('Login failed') unless $r->{ok} == 1;
$r = $knp->KNP_CMD_GET_OTUT_TICKET(reply_count => 1,
                                   otut_addr => $config{source_address});
is($r->{ok}, 1, 'requesting ticket');
$ticket = $r->{ticket};
$knp->close();

$knp = KNP::new($config{ots_host}, $config{ots_port});
$r = $knp->KNP_CMD_GET_OTUT_STRING(ticket => $ticket,
                                   in_otut_count => 1,
                                   reply_count_array => [2]);
is($r->{ok}, 1, 'successful fetch of OTUT string');
is($r->{out_otut_count}, 1, 'number of OTUT returned');
ok(length($r->{otut_array}[0]) > 0, 'presence of first OTUT');
$otut = $r->{otut_array}[0];
$knp->close();

# Ordinary packaging while providing the OTUT.
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'logging-in for packaging');
BAIL_OUT('Login failed') unless $r->{ok} == 1;
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{other1_address},
                                cc_field  => $config{other2_address},
                                tm_key_data => $tm_key_data,
                                nb_recipient => 2,
                                recipient_array => [{addr => $config{other1_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_PWD,
                                                     enc_key_data => ''},
                                                    {addr => $config{other2_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_PWD,
                                                     enc_key_data => ''}],
                                nb_pwd    => 2,
                                pwd_array => [{pwd => $config{other1_password},
                                               otut => $otut},
                                              {pwd => $config{other1_password},
                                               otut => $otut}],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'packaging mail to ' . $config{other1_address});
BAIL_OUT('packaging failed') unless $r->{ok} == 1;
$pkg_output = $r->{pkg_output};
$knp->close();

# Fetch the identity key of the sender so that we get the symmetric key.
$knp = KNP::new($config{iks_host}, $config{iks_port});
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});

is($r->{ok}, 1, 'successful signature key request for ' . $config{source_mid});
is($r->{owner_name}, $config{source_name}, 'checking name of key owner');
ok(length($r->{key_data}) > 0, 'presence of key data');
BAIL_OUT('Failed to fetch key of sender') unless $r->{ok} == 1;

$key_data = $r->{key_data};
$knp->close();

# Decrypt what was sent by the source to get the OTUT.
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $knp->get_signature_text($pkg_output),
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => "blarg",
                               pod_from => "somewhere",
                               subject => '');
$otut = $r->{otut};
is($r->{ok}, 1, 'successful decryption request');
ok(length($r->{sym_key_data}) > 0, 'presence of symmetric key data');
BAIL_OUT('Failed to decrypt the message') unless $r->{ok} == 1;
$knp->close();

# Fetch the encryption key of the target.
$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{source_address}]);
is($r->{ok}, 1, 'successful encryption key request for ' . $config{source_address});
ok(length($r->{key_array}[0]) > 0, 'presence of key data');
$encryption_key = $r->{key_array}[0];
$knp->close();

# Package the mail using the OTUT.
$knp = KNP::new($config{ops_host}, $config{ops_port});
$r = $knp->KNP_CMD_LOGIN_OTUT(otut => $otut);
is($r->{ok}, 1, 'successful OTUT login');
BAIL_OUT('OTUT login failed') unless $r->{ok} == 1;

$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 1,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{source_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => $encryption_key}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{other1_name},
                                from_addr => $config{other1_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'packaging while logged in with OTUT');
BAIL_OUT('packaging while logged in with OTUT failed') unless $r->{ok} == 1;
ok(length($r->{pkg_output}) > 0, 'presence of output data');
$pkg_output = $r->{pkg_output};
$knp->close();

# Check the validity of the OTUT we just used.
$knp = KNP::new($config{ots_host}, $config{ots_port});
$r = $knp->KNP_CMD_CHECK_OTUT_STRING(otut => $otut);
is($r->{ok}, 1, 'otut still valid once more');
$knp->close();

# Two OTUTs were demanded, make sure we can still login.
$knp = KNP::new($config{ops_host}, $config{ops_port});
$r = $knp->KNP_CMD_LOGIN_OTUT(otut => $otut);
ok($r->{ok} == 1, 'successful OTUT login');
$knp->close();

# Get our own signature key to decrypt the signature.
$knp = KNP::new($config{iks_host}, $config{iks_port});
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
is($r->{ok}, 1, 'successful signature key request' . $config{source_mid});
is($r->{owner_name}, $config{source_name}, 'validity of name of key owner');
ok(length($r->{key_data}) > 0, 'presence of key data');
BAIL_OUT('Failed to fetch key of sender') unless $r->{ok} == 1;
$key_data = $r->{key_data};
$knp->close();

# The source tries to decrypt the message that was sent using OTUT.
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'source login to decrypt OTUT message');
BAIL_OUT('Source login failed') unless $r->{ok} == 1;
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $knp->get_signature_text($pkg_output),
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => "",
                               pod_from => "somewhere",
                               subject => '');
is($r->{ok}, 1, 'decryption of message encrypted with OTUT');
$knp->close();
