use Test::More tests => 14;
use Teambox::KNP;
require 'config.pl';

#
# Fetch the timestamping key data for the source address.
#
$knp = KNP::new($config{iks_host}, $config{iks_port});
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
$tm_key_data = $r->{tm_key_data};
$knp->close();

# Fetch the key of the target.
$knp = KNP::new($config{eks_host}, $config{eks_port});
$r = $knp->KNP_CMD_GET_ENC_KEY(nb_address => 1,
                               address_array => [$config{target_address}]);
is($r->{ok}, 1, 'result of fetch for ' . $config{target_address});
ok(length($r->{key_array}[0]) > 0, 'length of returned key data');
$key_data = $r->{key_array}[0];
$knp->close();

#
# Simple package with PoD.
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'Logging in to package for PoD');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 2,
                                lang => 0,
                                to_field => $config{target_address},
                                cc_field => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => $key_data}],
                                nb_pwd => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject => 'this is a fake subject',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr => $config{source_address});
is($r->{ok}, 1, 'result of packaging request');
ok(length($r->{pkg_output}) > 0, 'length of output');
$knp->close();

#
# Simple package with PoD with Exchange address as PoD address.
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'Logging in to package for PoD');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 2,
                                lang => 0,
                                to_field => $config{target_address},
                                cc_field => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_ex},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => $key_data}],
                                nb_pwd => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject => 'this is a fake subject',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr => $config{source_ex});
is($r->{ok}, 1, 'result of packaging request (Exchange address as PoD address)');
ok(length($r->{pkg_output}) > 0, 'length of output');
$knp->close();

#
# Package a simple message, without PoD address this time.
#
$knp = KNP::new($config{kps_host}, $config{kps_port});
$r = $knp->KNP_CMD_LOGIN_USER(username => $config{source_username},
                              password => $config{source_password},
                              is_password => 1);
is($r->{ok}, 1, 'Logging in to package for PoD');
$r = $knp->KNP_CMD_PACKAGE_MAIL(pkg_type => 2,
                                lang => 0,
                                to_field => $config{target_address},
                                cc_field => '',
                                tm_key_data => $tm_key_data,
                                nb_recipient => 1,
                                recipient_array => [{addr => $config{target_address},
                                                     enc_type => $KNP::KNP_PKG_ENC_KEY,
                                                     enc_key_data => $key_data}],
                                nb_pwd => 0,
                                pwd_array => [],
                                from_name => $config{source_name},
                                from_addr => $config{source_address},
                                subject => 'this is a fake subject',
                                body_type => $KNP::KNP_PKG_BODY_TEXT,
                                body_text => 'this is a fake body',
                                body_html => '',
                                nb_attach => 0,
                                pod_addr => '');
is($r->{ok}, 1, 'result of packaging request (no PoD address)');
$sig_text = $knp->get_signature_text($r->{pkg_output});
$knp->close();

# Fetch the key of the sender.
$knp = KNP::new($config{iks_host}, $config{iks_port});
$r = $knp->KNP_CMD_GET_SIGN_KEY(key_id => $config{source_mid});
is($r->{ok}, 1, 'result of signature key fetch');
ok(length($r->{key_data}) > 0, 'length of returned key data > 0');
$key_data = $r->{key_data};
$knp->close();

# Try to decrypt the message now.
$knp = KNP::new($config{ous_host}, $config{ous_port});
$r = $knp->KNP_CMD_DEC_SYM_KEY(sig_text => $sig_text,
                               tm_key_data => $tm_key_data,
                               pub_key_data => $key_data,
                               inter_symkey_data => "",
                               pwd => '',
                               pod_from => $config{target_address},
                               subject => 'this is a fake subject');
is($r->{ok}, 1, 'result of decryption');
ok($r->{pod_date} > 0, 'PoD date');
$knp->close();

