#
# (c) 2015 FILIADATA GmbH
# 
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

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

  $self->foreman->modify_host_options->($self->foreman, $self) if($self->foreman->modify_host_options);

  return $self;
}

sub fact {
  my ($self, $fact) = @_;

  if( defined $fact && $self->{__puppet_fact__}->{$fact} ) {
    return $self->{__puppet_fact__}->{$fact};
  }

  # no fact found, run facter
  my $yaml = run "facter -y -p";
  $self->{__puppet_fact__} = Load($yaml);

  return $self->{__puppet_fact__}->{$fact};
}

sub get_user {
  my $self = shift;
  return $self->SUPER::get_user();
}

sub foreman {
  my $self = shift;
  return $self->{foreman};
}


1;

__END__

=pod

=head1 NAME

Foreman::Server - Object to handle Foreman host entries.

This Object inherits from I<Rex::Group::Entry::Server> and extends this object by some methods that are helpfull when dealing with foreman and puppet hosts.

This is an internal object of the I<Foreman> module and normaly won't get called from the outside world.

=head1 METHODS

=over 4

=item fact($factname)

Read the facter information of the host and returns the requested value.

=item foreman()

The foreman object which was used to initialize the object.

=back
 
=head1 COPYRIGHT

Copyright 2015 FILIADATA GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

