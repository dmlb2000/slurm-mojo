package Slurm::Mojo;

our $VERSION = '0.01';

use Authen::Krb5::Simple;

sub AuthRequest {
  my $c = shift;
  my $json = JSON->new->allow_nonref;
  my $httpdata = $json->allow_blessed->convert_blessed->decode( $c->req->body );
  die "need to pass username" unless exists $httpdata->{"username"};
  die "need to pass password" unless exists $httpdata->{"password"};
  my $user = $httpdata->{"username"};
  my $pass = $httpdata->{"password"};
  my $krb = Authen::Krb5::Simple->new();
  my $authen = $krb->authenticate($user, $pass);
  unless($authen) {
    my $errmsg = $krb->errstr();
    die "User: $user authentication failed: $errmsg\n";
  }
  return getpwnam($user);
};

