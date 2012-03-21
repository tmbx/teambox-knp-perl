#!/usr/bin/perl -w

#
# This try to see how the server will deal with corrupted Teambox
# signatures and content.
#

use MIME::Base64;
use Data::Dumper;
use Test::More tests => 6;
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
$good_signature = $knp->get_signature_text($r->{pkg_output});
$knp->close();

# Fetch the key for the sender.
$knp = KNP::new($config{iks_host}, $config{iks_port}, 3, 1);
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$key_data = $r->{key_data};
$knp->close();

#
# Shorten the signature.
#

$knp = KNP::new($config{ous_host}, $config{ous_port});
$short_signature = substr($good_signature, 0, length($good_signature) - 10);
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $short_signature,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption of shortened signature, from the end');
$knp->close();

#
# Add some crap at the end of the signature.
#

$hacked_signature = decode_base64($good_signature);
$hacked_signature .= "THIS IS CRAP ADDED AT THE END OF THE SIGNATURE!";
$hacked_signature = encode_base64($hacked_signature, "");

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $hacked_signature,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 1, 'decryption of lengthened, random crap added at the end');
$knp->close();

#
# Randomly hacked signature, modified base64 signature.
#

$hacked_signature = $good_signature;
for ($i = 0; $i < length($hacked_signature); $i++) {
  if ($i % 10 == 0) {
    substr $hacked_signature, $i, 1, "Z";
  }
}

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $hacked_signature,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption of hacked signature, randomly changed');
$knp->close();

#
# Randomly hacked signature, decode the signature, hack it, then
# reencode it.
#

$hacked_signature = decode_base64($good_signature);
for ($i = 0; $i < length($hacked_signature); $i++) {
  if ($i % 10 == 0) {
    substr $hacked_signature, $i, 1, 0;
  }
}
$hacked_signature = encode_base64($hacked_signature, "");

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $hacked_signature,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption of hacked signature, randomly internally changed');
$knp->close();

#
# Accurately hacked signature, change the signature type.
#

$hacked_signature = decode_base64($good_signature);
substr $hacked_signature, 20, 1, 2;
$hacked_signature = encode_base64($hacked_signature, "");

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $hacked_signature,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption of hacked signature, signature type changed');
$knp->close();

#
# Change the signature version.
#

$hacked_signature = decode_base64($good_signature);
substr $hacked_signature, 4, 1, "\0";
substr $hacked_signature, 5, 1, "\0";
substr $hacked_signature, 6, 1, "\0";
substr $hacked_signature, 7, 1, "\1";
$hacked_signature = encode_base64($hacked_signature, "");

$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $hacked_signature,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => $config{target_password},
                               pod_from => $config{target_address},
                               subject => ''
                              );
is($r->{ok}, 0, 'decryption of hacked signature, signature version changed');
$knp->close();
