package KNP;

use Carp;
use vars qw( $VERSION );
$VERSION = '0.04';

use POSIX qw(SIGALRM sigaction);
use Fcntl;
use strict;
use IO::Socket::SSL;
use IO::Select;
use Data::Buffer;
use Data::Dumper;
use Time::HiRes qw(ualarm);
require Exporter;

my $KNP_MAGIC_NUMBER = 2267283456;

our $KNP_PKG_BODY_CAT = $KNP_MAGIC_NUMBER + (6 << 8);
our $KNP_PKG_BODY_TEXT = $KNP_PKG_BODY_CAT + 1;
our $KNP_PKG_BODY_HTML = $KNP_PKG_BODY_CAT + 2;
our $KNP_PKG_BODY_BOTH = $KNP_PKG_BODY_CAT + 3;

our $KNP_PKG_ENC_CAT = $KNP_MAGIC_NUMBER + (5 << 8);
our $KNP_PKG_ENC_KEY = $KNP_PKG_ENC_CAT + 1;
our $KNP_PKG_ENC_PWD = $KNP_PKG_ENC_CAT + 2;

our $KNP_MAIL_PART_CAT = $KNP_MAGIC_NUMBER + (4 << 8);
our $KNP_MAIL_PART_IMPLICIT = $KNP_MAIL_PART_CAT + 1;
our $KNP_MAIL_PART_EXPLICIT = $KNP_MAIL_PART_CAT + 2;
our $KNP_MAIL_PART_UNKNOWN = $KNP_MAIL_PART_CAT + 3;
our $KNP_MAIL_PART_HTML_BODY = $KNP_MAIL_PART_CAT + 4;
our $KNP_MAIL_PART_TEXT_BODY = $KNP_MAIL_PART_CAT + 5;

my $KNP_UINT32 = 1;
my $KNP_UINT64 = 2;
my $KNP_STR = 3;

my $KNP_CMD_CAT	= $KNP_MAGIC_NUMBER + 512;
my $KNP_RES_CAT	= $KNP_MAGIC_NUMBER + 768;

my $KNP_RES_FAIL = $KNP_RES_CAT + 90;

my $KNP_CMD_LOGIN_ANON = $KNP_CMD_CAT + 10;
my $KNP_CMD_LOGIN_USER = $KNP_CMD_CAT + 11;
my $KNP_CMD_LOGIN_OTUT = $KNP_CMD_CAT + 12;
my $KNP_RES_LOGIN_OK   = $KNP_RES_CAT + 10;

my $KNP_CMD_GET_SIGN_KEY = $KNP_CMD_CAT + 30;
my $KNP_RES_GET_SIGN_KEY = $KNP_RES_CAT + 30;

my $KNP_CMD_GET_ENC_KEY_BY_ID = $KNP_CMD_CAT + 31;
my $KNP_RES_GET_ENC_KEY_BY_ID = $KNP_RES_CAT + 31;

my $KNP_CMD_GET_ENC_KEY = $KNP_CMD_CAT + 40;
my $KNP_RES_GET_ENC_KEY = $KNP_RES_CAT + 40;

my $KNP_CMD_PACKAGE_MAIL = $KNP_CMD_CAT + 50;
my $KNP_RES_PACKAGE_MAIL = $KNP_RES_CAT + 50;
my $KNP_RES_PACKAGE_FAIL = $KNP_RES_CAT + 51;
my $KNP_CMD_PACKAGE_LIC  = $KNP_CMD_CAT + 51;

my $KNP_CMD_GET_OTUT_TICKET = $KNP_CMD_CAT + 60;
my $KNP_RES_GET_OTUT_TICKET = $KNP_RES_CAT + 60;

my $KNP_CMD_GET_OTUT_STRING = $KNP_CMD_CAT + 70;
my $KNP_RES_GET_OTUT_STRING = $KNP_RES_CAT + 70;

my $KNP_CMD_GET_USER_KEY_ID = $KNP_CMD_CAT + 20;
my $KNP_RES_GET_USER_KEY_ID = $KNP_RES_CAT + 20;

my $KNP_CMD_GET_USER_INFO = $KNP_CMD_CAT + 20;
my $KNP_RES_GET_USER_INFO = $KNP_RES_CAT + 20;

my $KNP_CMD_CHECK_OTUT_STRING = $KNP_CMD_CAT + 61;
my $KNP_RES_CHECK_OTUT_STRING = $KNP_RES_CAT + 61;

my $KNP_CMD_DEC_SYM_KEY       = $KNP_CMD_CAT + 80;
my $KNP_RES_DEC_KEY_HALF      = $KNP_RES_CAT + 80;
my $KNP_RES_DEC_KEY_FULL      = $KNP_RES_CAT + 81;
my $KNP_RES_DEC_KEY_POD_ERROR = $KNP_RES_CAT + 82;
my $KNP_RES_DEC_KEY_BAD_PWD   = $KNP_RES_CAT + 83;
my $KNP_RES_DEC_KEY_NOT_AUTH  = $KNP_RES_CAT + 84;

my $KNP_RES_UPGRADE_PLUGIN = $KNP_RES_CAT + 91;
my $KNP_RES_UPGRADE_KPS = $KNP_RES_CAT + 92;

my $KNP_CMD_GET_KWS_TICKET = $KNP_CMD_CAT + 86;
my $KNP_RES_GET_KWS_TICKET = $KNP_RES_CAT + 86;

my $KNP_CMD_CONVERT_EXCHANGE = $KNP_CMD_CAT + 87;
my $KNP_RES_CONVERT_EXCHANGE = $KNP_RES_CAT + 87;

sub _request {
  my ($self, $type, $pb) = @_;
  my $hb;
  my ($major, $minor, $r, $n, $id, $sz, $sel);

  # Write part.
  $hb = Data::Buffer->new;
  $hb->put_int32($self->{major});
  $hb->put_int32($self->{minor});
  $hb->put_int32($type);

  if (defined($pb)) { $hb->put_int32($pb->length); }
  else { $hb->put_int32(0); }

  $SIG{PIPE} = sub { die "pipe broken\n" };

  $self->{conn}->print($hb->get_bytes($hb->length));
  if (defined($pb))
    { $self->{conn}->print($pb->get_bytes($pb->length)); }

  # Read part.
  $SIG{PIPE} = sub { };
  $SIG{ALRM} = sub { die "alarm\n" };

  ualarm($self->{timeout} * 1000);
  $n = $self->{conn}->read($r, 16);

  if ($n < 16) {
    $SIG{ALRM} = sub {};
    return undef;
  }

  $hb->put_bytes($r);

  $major = $hb->get_int32();
  $minor = $hb->get_int32();
  $id    = $hb->get_int32();
  $sz    = $hb->get_int32();

  if ($sz > 0) {
    $n = $self->{conn}->read($r, $sz);
    $pb->put_bytes($r);
  };

  $SIG{ALRM} = sub {};
  if ($n < $sz) { return undef; }

  return ($id, $major, $minor, $sz, $pb);
}

# Payload manipulations.
sub _put_string {
  my ($self, $pb, $string) = @_;

  $pb->put_int8($KNP_STR);
  $pb->put_int32(length($string));
  $pb->put_bytes($string);
}

sub _put_uint32 {
  my ($self, $pb, $n) = @_;

  $pb->put_int8($KNP_UINT32);
  $pb->put_int32($n);
}

# FIXME: 64 bits integers are not quite supported in this script.
sub _put_uint64 {
  my ($self, $pb, $n) = @_;

  $pb->put_int8($KNP_UINT64);
  $pb->put_int32(0);
  $pb->put_int32($n);
}

sub _get_string {
  my $self = shift;
  my ($b) = @_;
  my ($n, $s, $t);

  $t = $b->get_int8;
  confess "Wrong type.  Expected $KNP_STR, got $t."
    unless defined($t) && $t == $KNP_STR;
  $n = $b->get_int32;
  $s = $b->get_bytes($n);

  return $s;
}

sub _get_uint32 {
  my ($self, $b, $t) = @_;

  $t = $b->get_int8;
  confess "Wrong type.  Expected $KNP_UINT32, got $t."
    unless defined($t) && $t == $KNP_UINT32;
  return $b->get_int32;
}

# FIXME: 64 bits integer are not quite supported in this script.
sub _get_uint64 {
  my ($self, $b, $t) = @_;

  $t = $b->get_int8;
  confess "Wrong type.  Expected $KNP_UINT64, got $t."
    unless defined($t) && $t == $KNP_UINT64;
  $b->get_int32;
  return $b->get_int32;
}

sub _put_request_uint32 {
  my ($self, $f, $req, $buf) = @_;

  if (defined($req->{$f})) {
    $self->_put_uint32($buf, $req->{$f});
  } else {
    confess "Error: '$f' not provided.";
  }
}

sub _put_request_uint64 {
  my ($self, $f, $req, $buf) = @_;

  if (defined($req->{$f})) {
    $self->_put_uint64($buf, $req->{$f});
  } else {
    confess "Error: '$f' not provided.";
  }
}

sub _put_request_string {
  my ($self, $f, $req, $buf) = @_;

  if (defined($req->{$f})) {
    $self->_put_string($buf, $req->{$f});
  } else {
    confess "Error: '$f' not provided.";
  }
}

sub KNP_CMD_GET_SIGN_KEY {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz);

  $self->_put_request_uint64('key_id', $req, $buf);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_SIGN_KEY, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@ }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_GET_SIGN_KEY) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  if ($major >= 3) {
    $rep{tm_key_data} = $self->_get_string($buf);
  }
  $rep{key_data} = $self->_get_string($buf);
  $rep{owner_name} = $self->_get_string($buf);
  $rep{major} = $major;
  $rep{minor} = $minor;

  return \%rep;
}

sub KNP_CMD_GET_KWS_TICKET {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz, $i, $n);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_KWS_TICKET, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_GET_KWS_TICKET) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{ticket} = $self->_get_string($buf);

  return \%rep;
}

sub KNP_CMD_GET_ENC_KEY_BY_ID {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz, $i, $n);

  $self->_put_request_uint64('key_id', $req, $buf);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_ENC_KEY_BY_ID, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_GET_ENC_KEY_BY_ID) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{tm_key_data} = $self->_get_string($buf);
  $rep{key_data} = $self->_get_string($buf);
  $rep{owner_name} = $self->_get_string($buf);

  return \%rep;
}

sub KNP_CMD_CONVERT_EXCHANGE {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz, $i, $n);

  $self->_put_request_uint32('nb_address', $req, $buf);

  foreach $i (@{$req->{address_array}})
    { $self->_put_string($buf, $i); }

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_CONVERT_EXCHANGE, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_CONVERT_EXCHANGE) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{nb_address} = $self->_get_uint32($buf);
  $rep{email_array} = [];

  for ($i = 0; $i < $rep{nb_address}; $i++) {
    my $s = $self->_get_string($buf);
    push @{$rep{email_array}}, $s;
  }

  return \%rep;
}

sub KNP_CMD_GET_ENC_KEY {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz, $i, $n);

  $self->_put_request_uint32('nb_address', $req, $buf);
  $n = $req->{'nb_address'};

  foreach $i (@{$req->{address_array}})
    { $self->_put_string($buf, $i); }

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_ENC_KEY, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_GET_ENC_KEY) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
#  if ($major >= 3) {
#    $rep{tm_key_data} = $self->_get_string($buf);
#  }
  $rep{nb_key} = $self->_get_uint32($buf);
  $rep{key_array} = [];
  for ($i = 0; $i < $rep{nb_key}; $i++) {
    my $s = $self->_get_string($buf);
    push @{$rep{key_array}}, $s;
  }

  return \%rep;
}

sub KNP_CMD_GET_USER_INFO {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz, $i, $n);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_USER_INFO, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id = $KNP_RES_GET_USER_INFO) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{mid} = $self->_get_uint64($buf);
  $rep{nb_domain} = $self->_get_uint32($buf);
  for ($i = 0; $i < $rep{nb_domain}; $i++) {
    my $s = $self->_get_string($buf);
    push @{$rep{domain_array}}, $s;
  }
  if ($rep{major} >= 4) {
    $rep{kpg_is_used} = $self->_get_uint32($buf);

    # Read the KPG info if available.
    if ($rep{kpg_is_used}) {
      $rep{kpg_address} = $self->_get_string($buf);
      $rep{kpg_port} = $self->_get_uint32($buf);
    }
  }

  return \%rep;
}

sub KNP_CMD_GET_OTUT_STRING {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($i, $major, $minor, $id, $sz);

  $self->_put_request_string('ticket', $req, $buf);
  $self->_put_request_uint32('in_otut_count', $req, $buf);

  foreach $i (@{$req->{reply_count_array}})
    { $self->_put_uint32($buf, $i); }

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_OTUT_STRING, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@ }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_GET_OTUT_STRING) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{out_otut_count} = $self->_get_uint32($buf);
  $rep{otut_array} = [];
  for ($i = 0; $i < $rep{out_otut_count}; $i++) {
    my $s = $self->_get_string($buf);
    push @{$rep{otut_array}}, $s;
  }

  return \%rep;
}

sub KNP_CMD_GET_OTUT_TICKET {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz);

  $self->_put_request_uint32('reply_count', $req, $buf);
  $self->_put_request_string('otut_addr', $req, $buf);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_GET_OTUT_TICKET, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@ }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_GET_OTUT_TICKET) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }
  confess "Empty reply." unless(defined($buf));

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{ticket} = $self->_get_string($buf);
  return \%rep;
}

sub KNP_CMD_LOGIN_USER {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor);

  $self->_put_request_string('username', $req, $buf);
  $self->_put_request_string('password', $req, $buf);
  if ($self->{major} >= 3) {
    $self->_put_request_uint32('is_password', $req, $buf);
  }

  eval {
    ($id, $major, $minor) = $self->_request($KNP_CMD_LOGIN_USER, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@ };
  if (!$id) { return {ok => 0}; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_LOGIN_OK) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  elsif ($id == $KNP_RES_UPGRADE_KPS) { return {ok => 0, upgrade => 'kps'}; }
  elsif ($id == $KNP_RES_UPGRADE_PLUGIN) { return {ok => 0, upgrade => 'plugin'}; }
  else { confess "Unknown reply type: ". ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  if ($self->{major} == 3) {
    $rep{token} = $self->_get_string($buf);
  }

  return \%rep;
}

sub KNP_CMD_CHECK_OTUT_STRING {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz);

  $self->_put_request_string('otut', $req, $buf);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_CHECK_OTUT_STRING, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_CHECK_OTUT_STRING) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{otut_uses} = $self->_get_uint32($buf);

  return \%rep;
}

sub KNP_CMD_LOGIN_OTUT {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor);

  $self->_put_request_string('otut', $req, $buf);

  eval {
    ($id, $major, $minor) = $self->_request($KNP_CMD_LOGIN_OTUT, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }
  elsif ($@) { die $@ };

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_LOGIN_OK) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: ". ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{enc_password} = $self->_get_string($buf);

  return \%rep;
}

sub _KNP_CMD_PACKAGE_MAIL_recipients {
  my $self = shift;
  my $n = shift;
  my $buf = shift;
  my @rcps = @_;

  for (my $i = 0; $i < $n; $i++) {
    $self->_put_request_string('addr', $rcps[$i], $buf);
    $self->_put_request_uint32('enc_type', $rcps[$i], $buf);
    $self->_put_request_string('enc_key_data', $rcps[$i], $buf);
  }
}

sub _KNP_CMD_PACKAGE_MAIL_passwords {
  my $self = shift;
  my $n = shift;
  my $buf = shift;
  my @pwds = @_;

  for (my $i = 0; $i < $n; $i++) {
    $self->_put_request_string('pwd', $pwds[$i], $buf);
    $self->_put_request_string('otut', $pwds[$i], $buf);
  }
}

sub _KNP_CMD_PACKAGE_MAIL_attachments {
  my $self = shift;
  my $n = shift;
  my $buf = shift;
  my @attchs = @_;

  for (my $i = 0; $i < $n; $i++) {
    $self->_put_request_uint32('type', $attchs[$i], $buf);
    $self->_put_request_string('encoding', $attchs[$i], $buf);
    $self->_put_request_string('mime_type', $attchs[$i], $buf);
    $self->_put_request_string('name', $attchs[$i], $buf);
    $self->_put_request_string('payload', $attchs[$i], $buf);
  }
}

sub KNP_CMD_PACKAGE_MAIL {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz);

  $self->_put_request_uint32('pkg_type', $req, $buf);
  if ($self->{major} >= 2) {
    $self->_put_request_uint32('lang', $req, $buf);
  }
  $self->_put_request_string('to_field', $req, $buf);
  $self->_put_request_string('cc_field', $req, $buf);
#  if ($self->{major} >= 3) {
#    $self->_put_request_string('tm_key_data', $req, $buf);
#  }
  $self->_put_request_uint32('nb_recipient', $req, $buf);
  $self->_KNP_CMD_PACKAGE_MAIL_recipients($req->{nb_recipient}, $buf, @{$req->{recipient_array}});
  $self->_put_request_uint32('nb_pwd', $req, $buf);
  $self->_KNP_CMD_PACKAGE_MAIL_passwords($req->{nb_pwd}, $buf, @{$req->{pwd_array}});
  $self->_put_request_string('from_name', $req, $buf);
  $self->_put_request_string('from_addr', $req, $buf);
  $self->_put_request_string('subject', $req, $buf);
  $self->_put_request_uint32('body_type', $req, $buf);
  $self->_put_request_string('body_text', $req, $buf);
  $self->_put_request_string('body_html', $req, $buf);
  $self->_put_request_uint32('nb_attach', $req, $buf);
  $self->_KNP_CMD_PACKAGE_MAIL_attachments($req->{nb_attach}, $buf, @{$req->{attach_array}});
  $self->_put_request_string('pod_addr', $req, $buf);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_PACKAGE_MAIL, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_PACKAGE_MAIL) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) {
    return {ok => 0};
  }
  elsif ($self->{major} >= 4 && $id == $KNP_RES_PACKAGE_FAIL) {
    return {ok => 0,
            fail_message => $self->_get_string($buf) };
  }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{pkg_output} = $self->_get_string($buf);
  $rep{ksn} = $self->_get_string($buf);
  $rep{sym_key} = $self->_get_string($buf);

  return \%rep;
}

sub KNP_CMD_PACKAGE_LIC {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz);

  confess "License packaging is not supported in versions earlier than KNP 3"
    if ($self->{major} < 3);

  $self->_put_request_uint32('pkg_type', $req, $buf);
  $self->_put_request_uint32('lang', $req, $buf);
  $self->_put_request_string('to_field', $req, $buf);
  $self->_put_request_string('cc_field', $req, $buf);
  $self->_put_request_uint32('nb_recipient', $req, $buf);
  $self->_KNP_CMD_PACKAGE_MAIL_recipients($req->{nb_recipient}, $buf, @{$req->{recipient_array}});
  $self->_put_request_uint32('nb_pwd', $req, $buf);
  $self->_KNP_CMD_PACKAGE_MAIL_passwords($req->{nb_pwd}, $buf, @{$req->{pwd_array}});
  $self->_put_request_string('from_name', $req, $buf);
  $self->_put_request_string('from_addr', $req, $buf);
  $self->_put_request_string('subject', $req, $buf);
  $self->_put_request_uint32('body_type', $req, $buf);
  $self->_put_request_string('body_text', $req, $buf);
  $self->_put_request_string('body_html', $req, $buf);
  $self->_put_request_uint32('nb_attach', $req, $buf);
  $self->_KNP_CMD_PACKAGE_MAIL_attachments($req->{nb_attach}, $buf, @{$req->{attach_array}});
  $self->_put_request_string('pod_addr', $req, $buf);
  $self->_put_request_uint32('license_lim', $req, $buf);
  $self->_put_request_uint32('license_max', $req, $buf);
  $self->_put_request_string('license_kdn', $req, $buf);

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_PACKAGE_LIC, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }

  if (!defined($id)) { $rep{ok} = 0; }
  if ($id == $KNP_RES_PACKAGE_MAIL) { $rep{ok} = 1; }
  elsif ($id == $KNP_RES_FAIL) { return {ok => 0}; }
  else { confess "Unknown reply type: " . ($id - $KNP_RES_CAT) . "."; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{pkg_output} = $self->_get_string($buf);
  $rep{ksn} = $self->_get_string($buf);
  $rep{sym_key} = $self->_get_string($buf);

  return \%rep;
}

sub KNP_CMD_DEC_SYM_KEY {
  my $self = shift;
  my $req = {@_};
  my %rep;
  my $buf = Data::Buffer->new;
  my ($id, $major, $minor, $sz);

  $self->_put_request_string('sig_text', $req, $buf);
  if ($self->{major} >= 3) {
    $self->_put_request_string('tm_key_data', $req, $buf);
  }
  $self->_put_request_string('pub_key_data', $req, $buf);
  $self->_put_request_string('inter_symkey_data', $req, $buf);
  $self->_put_request_string('pwd', $req, $buf);
  $self->_put_request_string('pod_from', $req, $buf);
  if ($self->{major} >= 2) {
    $self->_put_request_string('subject', $req, $buf);
  }

  eval {
    ($id, $major, $minor, $sz, $buf) = $self->_request($KNP_CMD_DEC_SYM_KEY, $buf);
  };
  if ($@ eq "alarm\n") { return {ok => 0, timeout => 1}; }

  if (!defined($id)) { $rep{ok} = 0; }

  if ($id == $KNP_RES_DEC_KEY_HALF)      { $rep{ok} = 1;
                                           $rep{state} = 'half'; }
  if ($id == $KNP_RES_DEC_KEY_FULL)      { $rep{ok} = 1;
                                           $rep{state} = 'full'; }
  if ($id == $KNP_RES_DEC_KEY_POD_ERROR) { $rep{ok} = 0;
                                           $rep{state} = 'POD error'; }
  if ($id == $KNP_RES_DEC_KEY_BAD_PWD)   { $rep{ok} = 0;
                                           $rep{state} = 'Bad password'; }
  if ($id == $KNP_RES_DEC_KEY_NOT_AUTH)  { $rep{ok} = 0;
                                           $rep{state} = 'Not authorized'; }
  if ($id == $KNP_RES_FAIL)              { $rep{ok} = 0; }

  if ($rep{ok} == 0) { return \%rep; }

  $rep{major} = $major;
  $rep{minor} = $minor;
  $rep{sym_key_data} = $self->_get_string($buf);
  $rep{otut} = $self->_get_string($buf);
  if ($rep{major} >= 3) {
    $rep{pod_date} = $self->_get_uint32($buf);
  }

  return \%rep;
}

my $KSIGSTART = "----- KRYPTIVA SIGNATURE START -----";
my $KSIGEND   = "----- KRYPTIVA SIGNATURE END -----";

sub get_signature_text {
  my $self = shift;
  my ($s) = shift;
  my @l = split(/\n/, $s);
  my ($t, $do) = ("", 0);

  foreach my $i (@l) {
    if ($i =~ m/$KSIGEND/)   { $do = 0; }
    if ($do) { $t .= $i; }
    if ($i =~ m/$KSIGSTART/) { $do = 1; }
  }

  return $t;
}

my $KENCSTART = "----- KRYPTIVA ENCRYPTED DATA START -----";
my $KENCEND   = "----- KRYPTIVA ENCRYPTED DATA END -----";

sub get_encrypted_text {
  my ($s) = shift;
  my @l = split(/\n/, $s);
  my ($t, $do) = ("", 0);

  foreach my $i (@l) {
    if ($i =~ m/$KENCEND/)   { $do = 0; }
    if ($do) { $t .= $i; }
    if ($i =~ m/$KENCSTART/) { $do = 1; }
  }

  return $t;
}

# Fast file reader which loads a big file in memory all at once.
sub get_file_content {
  my $self = shift;
  my $f = shift;
  my (@s, $l, $c);

  @s = stat $f;
  if (@s) { $l = $s[7]; }
  sysopen F, $f, O_RDONLY;
  sysread F, $c, $l;
  close F;

  return $c;
}

sub fetch_sig_key {
  my ($self, $key_id) = shift;
  my $r;

  confess 'Not connected' unless defined($self->{conn});

  $r = KNP_CMD_GET_SIG_KEY(key_id => $key_id);
  return $r->{data};
}

sub timeout {
  my ($self, $timeout) = @_;
  $self->{timeout} = $timeout;
}

sub new {
  my ($a, $p, $major, $minor) = @_;
  my $self = { conn => undef,
               address => $a,
               port => $p,
               major => $major,
               minor => $minor };

  if (!defined($self->{major})) { $self->{major} = 3; }
  if (!defined($self->{minor})) { $self->{minor} = 1; }

  $self->{timeout} = 10000;
  $self->{conn} = new IO::Socket::SSL(PeerAddr => $self->{address},
                                      PeerPort => $self->{port},
                                      SSL_version => 'SSLv3',
                                      # This is a *WEAK* cipher that
                                      # can actually be decrypted by
                                      # the ssldump in Linux
                                      SSL_cipher_list => 'RC4-MD5');
  confess "SSL connection to $self->{address}:$self->{port} failed."
    unless (defined($self->{conn}));

  return bless $self, 'KNP';
}

sub close {
  my ($self) = @_;

  close $self->{conn};
  $self->{conn} = undef;
}

1;
