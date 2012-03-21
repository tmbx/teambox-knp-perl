#!/usr/bin/perl -W

use Data::Dumper;
use Test::More tests => 3;
use Teambox::KNP;
require 'config.pl';

my %pkg_cmd = (pkg_type => 0,
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
               body_text => '',
               body_html => '',
               nb_attach => 0,
               pod_addr  => '');

#
# Signing a weird binary text body.
#

$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;

$pkg_cmd{body_text} = $knp->get_file_content('/bin/nano');

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'weird binary text body');
$knp->close();

#
# Signing a both a weird binary text body and a weird HTML text body.
#

$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
$pkg_cmd{body_type} = $KNP::KNP_PKG_BODY_BOTH;
$pkg_cmd{body_html} = $knp->get_file_content('/bin/ls');

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'weird binary text and HTML body');
$knp->close();

#
# Signing a message that looks like a Teambox message already.
#

$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
$pkg_cmd{body_type} = $KNP::KNP_PKG_BODY_TEXT;
$pkg_cmd{body_html} = '';
$pkg_cmd{body_text} = "----- KRYPTIVA SIGNED MESSAGE -----
Ce courriel assemblé par le protocole Kryptiva, le
système de sécurité utilisé par la suite Teambox(R).
Pour plus d'info, visitez: http://www.teambox.co
--
This email packaged using Kryptiva protocol, the
security system underneath the Teambox(R) suite.
For more information, visit: http://www.teambox.co

----- KRYPTIVA SIGNATURE START -----
AvWVqAAAAAIAAAABAAAAAAAAAAoCAQAAAADOAQAIAAAAAwAAAAECABS07byau4gG1rTXK0RN
dUvALusQNwMAFLxLaennb8bt6MGdX4GILcFi8H7HBAAUvEtp6edvxu3owZ1fgYgtwWLwfscF
ABTaOaPuXmtLDTJVv++VYBiQr9gHCQYAFNkqnJkN1uhbnVx2hePqIcUf3ngFBwAUKWAAWY/Q
pTl0fymIXjHgPw1fuRwIABRrlFyqVM6uh+i6bs6b0ARaCWSGFBEAGAAAAAAAAAAKRgPeTgAC
dqIAAAAAAAACRBMABAAAAAEAAACCBADJNE/B7fTO/WwitLXVGHsPvvkRxZue/IqRLqtFVhbM
vmRnaE5SPuoxHNj18peYUgkYqBJZzHwc8/LrncGDLheHHnzdW30MSy6NGAKAkjhiXD0eqyw0
Nx7Nl12jgtTGE/7M6XDl/s0b7+rfpMZrhzOFn0V4MAaYXFG2Ow2jBF+lCg==
----- KRYPTIVA SIGNATURE END -----";

$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
is($r->{ok}, 1, 'teambox stuff in content');
$knp->close();
