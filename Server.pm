package Foreman::Server;

use common::sense;

use Rex -base;
use Rex::CMDB;
use DM::Helper;


use base qw(Rex::Group::Entry::Server);


sub new {
  my $that = shift;
  my $proto = ref($that) || $that;
  my $self = $proto->SUPER::new(@_);

  bless($self, $proto);

  my $cmdb = get cmdb(undef, $self->{name});
  for my $key (keys %{ $cmdb }) {
    if($key =~ m/\.enc$/) {
      my ($_tk) = ($key =~ m/^(.*)\./);
      $self->{$_tk} = decrypt_string($cmdb->{$key});
    }
    else {
      $self->{$key} = $cmdb->{$key};
    }
  }

  if($self->{deploy_user}) {
    $self->{auth}->{user} = $self->{deploy_user};
  }
  if($self->{deploy_user_password}) {
    my $decr_pw;
    eval {
      $decr_pw = decrypt_string($self->{deploy_user_password});
      1;
    } or do {
      $decr_pw = $self->{deploy_user_password};
    };

    $self->{auth}->{password} = $decr_pw;
  }
  if($self->{auth_type}) {
    $self->{auth}->{auth_type} = $self->{auth_type};
  }


  return $self;
}

sub fact {
  my ($self, $fact) = @_;

  if( defined $fact && $self->{__puppet_fact__}->{$fact} ) {
    return $self->{__puppet_fact__}->{$fact};
  }

  # no fact found, run facter
  my $yaml = run "facter -y";
  $self->{__puppet_fact__} = Load($yaml);

  return $self->{__puppet_fact__}->{$fact};
}

sub get_user {
  my $self = shift;
  return $self->{auth}->{user};
}


1;
