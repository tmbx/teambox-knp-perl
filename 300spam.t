#!/usr/bin/perl -W

use Test::More tests => 6;
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
$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
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
                                nb_attach => 1,
                                attach_array => [{type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => 'some.file.1',
                                                  payload => 'smallish payload'}],
                                pod_addr  => '');
is($r->{ok}, 1, 'packaging with attachment');
$knp->close();

#
# Packaging the GTUBE.
#

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
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
                                body_text => 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => '');
is($r->{ok}, 0, 'failed packaging of the GTUBE');
ok(defined($r->{fail_message}) && length($r->{fail_message}) > 0, "failure reason provided");
$knp->close();

#
# Packaging the GTUBE as an attachment.
#

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
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
                                nb_attach => 1,
                                attach_array => [{type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => 'some.file.1',
                                                  payload => 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'}],
                                pod_addr  => '');
is($r->{ok}, 0, 'failed packaging with attached GTUBE');
ok(defined($r->{fail_message}) && length($r->{fail_message}) > 0, "failure reason provided");
$knp->close();

#
# Packaging a binary attachment.
#

$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
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
                                nb_attach => 1,
                                attach_array => [{type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                                  encoding => '',
                                                  mime_type => '',
                                                  name => 'some.file.1',
                                                  payload => $knp->get_file_content('/bin/ls')}],
                                pod_addr  => '');
is($r->{ok}, 1, 'packaging with a binary attachment');
$knp->close();
