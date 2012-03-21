#!/usr/bin/perl -W

use Data::Dumper;
use Test::More tests => 4;
use Teambox::KNP;
require 'config.pl';

my %pkg_cmd = (pkg_type => 1,
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

#
# One explicit attachment, small size
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;

$pkg_cmd{nb_attach} = 1;
$pkg_cmd{attach_array} = [{type => $KNP::KNP_MAIL_PART_EXPLICIT,
                           encoding => '',
                           mime_type => '',
                           name => '/etc/fstab',
                           payload => $knp->get_file_content('/etc/fstab')
                          }];

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'single attachment, small size');
$knp->close();

#
# Several explicit attachments, small size
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;

$pkg_cmd{nb_attach} = 10;
$pkg_cmd{attach_array} = [];
for ($i = 0; $i < 10; $i++) {
  $pkg_cmd{attach_array}[$i] = {type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                 encoding => '',
                                 mime_type => '',
                                 name => '/etc/fstab',
                                 payload => $knp->get_file_content('/etc/fstab')
                                };
}

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'several attachment, small size');
$knp->close();

#
# Hundreds explicit attachments, small size
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;

$pkg_cmd{nb_attach} = 100;
$pkg_cmd{attach_array} = [];
for ($i = 0; $i < 100; $i++) {
  $pkg_cmd{attach_array}[$i] = {type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                 encoding => '',
                                 mime_type => '',
                                 name => '/etc/fstab',
                                 payload => $knp->get_file_content('/etc/fstab')
                                };
}

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'hundreds of attachments, small size');
$knp->close();

#
# Several attachments, medium size
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;

$pkg_cmd{nb_attach} = 10;
$pkg_cmd{attach_array} = [];
for ($i = 0; $i < 10; $i++) {
  $pkg_cmd{attach_array}[$i] = {type => $KNP::KNP_MAIL_PART_EXPLICIT,
                                 encoding => '',
                                 mime_type => '',
                                 name => '/etc/fstab',
                                 payload => $knp->get_file_content('/etc/fstab')
                                };
}

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'hundreds of attachments, small size');
$knp->close();
