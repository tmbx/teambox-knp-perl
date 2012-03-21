#!/usr/bin/perl

use Test::More tests => 21;
use Teambox::KNP;
require 'config.pl';

#
# Simple encryption of a text message.
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 0,
                                recipient_array => [],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => "bar\n",
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'succesful packaging');
ok(length($r->{pkg_output}) > 0, 'presence of result text');
ok(length($r->{ksn}) > 0, 'presence of KSN');
ok(length($r->{sym_key}) == 0, 'absence of symmetric key');
$knp->close();

#
# Simple encryption of an text message (Exchange addresses)
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_ex},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => "bar\n",
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'succesful packaging (Exchange address)');
ok(length($r->{pkg_output}) > 0, 'presence of result text');
ok(length($r->{ksn}) > 0, 'presence of KSN');
ok(length($r->{sym_key}) == 0, 'absence of symmetric key');
$knp->close();

#
# Simple encryption of an HTML message.
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_HTML,
                                body_text => '',
                                body_html => 'this is a fake body',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'succesful packaging');
ok(length($r->{pkg_output}) > 0, 'presence of result text');
ok(length($r->{ksn}) > 0, 'presence of KSN');
ok(length($r->{sym_key}) == 0, 'absence of symmetric key');
$knp->close();

#
# Try with a blank To.
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => '',
                                cc_field  => '',
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_HTML,
                                body_text => '',
                                body_html => 'this is a fake body',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'successful packaging (blank To)');
$knp->close();

#
# Try with a blank From Name.
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => '',
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_HTML,
                                body_text => '',
                                body_html => 'this is a fake body',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 1, 'succesful packaging (blank From Name)');
$knp->close();

#
# Try with a blank From Address
#
$knp = KNP::new($config{kps_host}, $config{kps_port}, 2, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => '',
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_HTML,
                                body_text => '',
                                body_html => 'this is a fake body',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 0, 'failed packaging (blank From Address)');
$knp->close();
