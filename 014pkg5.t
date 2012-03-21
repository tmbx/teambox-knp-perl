#!/usr/bin/perl -W

use Test::More tests => 10;
use Teambox::KNP;
require 'config.pl';

#
# Fetch the timestamping key data for the source address.
#
$knp = KNP::new($config{iks_host}, $config{iks_port});
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$knp->close();

#
# Packaging a single attachment with signature.
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
ok($r->{ok} == 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                nb_recipient => 0,
                                tm_key_data => $tm_key_data,
                                recipient_array => [],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 3,
                                attach_array => [{type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => 'some.file.1',
                                                  payload => 'smallish payload'},
                                                 {type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => 'some.file.2',
                                                  payload => 'smallish payload for attachment in the middle.'},
                                                 {type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => 'some.file.3',
                                                  payload => 'smallish payload'}],
                                pod_addr  => '');
is($r->{ok}, 1, 'succesful packaging');
ok(length($r->{pkg_output}) > 0, 'presence of result text');
ok(length($r->{ksn}) > 0, 'presence of KSN');
ok(length($r->{sym_key}) == 0, 'absence of symmetric key');
$knp->close();

#
# Packaging a big attachment with signature.
#

$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 0,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 0,
                                recipient_array => [],
                                nb_pwd    => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 1,
                                attach_array => [{type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => '/usr/bin/emacs',
                                                  payload => $knp->get_file_content('/usr/bin/emacs')
                                                 }],
                                pod_addr  => '');
is($r->{ok}, 1, 'succesful packaging');
ok(length($r->{pkg_output}) > 0, 'presence of result text (' . length($r->{pkg_output}) . ')');
ok(length($r->{ksn}) > 0, 'presence of KSN (' . length($r->{ksn}) . ')');
ok(length($r->{sym_key}) == 0, 'absence of symmetric key');
$knp->close();

