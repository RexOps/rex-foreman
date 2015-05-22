package Foreman::Server;

use common::sense;

use Rex -base;
use Rex::CMDB;

use base qw(Rex::Group::Entry::Server);


sub new {
  my $that = shift;
  my $proto = ref($that) || $that;
  my $self = $proto->SUPER::new(@_);

  bless($self, $proto);

  my $cmdb = get cmdb(undef, $self->{name});
  for my $key (keys %{ $cmdb }) {
    $self->{$key} = $cmdb->{$key};
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
