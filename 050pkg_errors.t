#!/usr/bin/perl -W

# Test for PoD and password encryption.

use Test::More tests => 6;
use Teambox::KNP;
require 'config.pl';

#
# Fetch the timestamping key data for the source address.
#
$knp = KNP::new($config{iks_host}, $config{iks_port}, 4, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$knp->close();

# Fetch the target key.
$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 3,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 0,
                                recipient_array => [{addr => $config{source_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_PWD,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [{pwd => $config{target_password},
                                               otut => ''}],
                                from_name => $config{source_name} . "(Blarg)",
                                from_addr => $config{source_address},
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => $config{source_address});
is($r->{ok}, 0, 'unsuccesful packaging (incorrect from name)');
ok(defined($r->{fail_message}) && length($r->{fail_message}) > 0, "failure reason provided");
$knp->close();

#
# Fetch the timestamping key data for the source address.
#
$knp = KNP::new($config{iks_host}, $config{iks_port}, 4, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$knp->close();

# Fetch the target key.
$knp = KNP::new($config{kps_host}, $config{kps_port}, 4, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'successful login');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 3,
                                lang => 1,
                                to_field  => $config{source_address},
                                cc_field  => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 0,
                                recipient_array => [{addr => $config{source_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_PWD,
                                                     enc_key_data => ''}],
                                nb_pwd    => 0,
                                pwd_array => [{pwd => $config{target_password},
                                               otut => ''}],
                                from_name => $config{source_name},
                                from_addr => 'blarg@blarg.com',
                                subject   => 'this is a fake message',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr  => $config{source_address});
is($r->{ok}, 0, 'unsuccesful packaging (incorrect from address)');
ok(defined($r->{fail_message}) && length($r->{fail_message}) > 0, "failure reason provided");
$knp->close();

