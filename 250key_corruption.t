#!/usr/bin/perl -w

#
# This try to see how the server will deal with corrupted decryption
# keys.
#

use MIME::Base64;
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
# Simple encryption/decryption with password.
#

#First, encrypt something for the target.
$knp = KNP::new($config{kps_host}, $config{kps_port}, 3, 1);
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
BAIL_OUT('login failed') unless $r->{ok} == 1;
$r = $knp->KNP_CMD_PACKAGE_MAIL(%pkg_cmd);
BAIL_OUT('encryption failed') unless $r->{ok} == 1;
$signature = $knp->get_signature_text($r->{pkg_output});
$knp->close();

# Fetch the key for the sender.
$knp = KNP::new($config{iks_host}, $config{iks_port}, 3, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$good_tm_key_data = $r->{tm_key_data};
$good_key_data = $r->{key_data};
$knp->close();

#
# Shorten the key from the end.
#

$short_key_data = substr($good_key_data, 0, length($good_key_data) - 10);

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               tm_key_data => $good_tm_key_data,
                               pub_key_data => $short_key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption with shortened key, from the end');
$knp->close();

#
# Shorten the key from the start.
#

$short_key_data = substr($good_key_data, 10, length($good_key_data) - 10);

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               tm_key_data => $good_tm_key_data,
                               pub_key_data => $short_key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption with shortened key, from the start');
$knp->close();

#
# Hack the key internally.
#

$hacked_key_data = decode_base64($good_key_data);
for ($i = 0; $i < length($hacked_key_data); $i++) {
  if ($i % 10 == 0) {
    substr $hacked_key_data, $i, 1, "\030";
  }
}
$hacked_key_data = encode_base64($good_key_data, "");

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               tm_key_data => $good_tm_key_data,
                               pub_key_data => $hacked_key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption with hacked key, internally changed');
$knp->close();

#
# Hack the timestamp key internally.
#

$hacked_tm_key_data = decode_base64($good_tm_key_data);
for ($i = 0; $i < length($hacked_tm_key_data); $i++) {
  if ($i % 10 == 0) {
    substr $hacked_key_data, $i, 1, '\030';
  }
}
$hacked_tm_key_data = encode_base64($good_tm_key_data, "");

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $signature,
                               tm_key_data => $hacked_tm_key_data,
                               pub_key_data => $good_key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption with hacked timestamp key, internally changed');
$knp->close();

