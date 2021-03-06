#
# (c) 2015 FILIADATA GmbH
# 
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Foreman;

use Moose;
use MooseX::Params::Validate;
use namespace::autoclean;
use Carp;

use LWP::UserAgent;
use JSON::XS;
use MIME::Base64;
use YAML;
use Rex -base;
use Foreman::Server;
use Data::Dumper;
use Storable;
use URI::Escape;

no warnings 'redefine';

has url      => (is => 'ro', isa => 'Str', required => 1);
has user     => (is => 'ro', isa => 'Str', required => 1);
has password => (is => 'ro', isa => 'Str', required => 1);
has ua       => (is => 'ro', default => sub { LWP::UserAgent->new; });
has cache    => (is => 'ro', default => sub { "/tmp/foreman.cache" });

has modify_host_options => (is => 'ro', default => sub {});

sub get_hosts {
  my $self = shift;
  my $option;
  if(ref $_[0] eq "HASH") {
    $option = shift;
  }
  else {
    $option = { @_ };
  }

  if(exists $option->{service}) {
    $option->{class} = $option->{service};
    delete $option->{service};
  }

  my $retrieve_host_data = $option->{retrieve_host_data};
  delete $option->{retrieve_host_data};

  $self->search($self->_build_query_string(%{ $option }), $retrieve_host_data);
}

sub get_host {
  my $self = shift;
  my (%option) = validated_hash(
    \@_,
    host => { isa => 'Str' },
  );

  my $host_data = $self->get_host_parameters(host => $option{host});
  return Foreman::Server->new(name => $option{host}, foreman => $self, %{ $host_data });
}

sub search {
  my $self = shift;
  my $searchstring = shift;
  my $retrieve_host_data = shift // 1;

  my $hosts = $self->_request('api/hosts', $self->_build_query_string(
      search   => $searchstring,
      per_page => 9999));

  my @hosts = map { $_ = $_->{host}->{name} } @{ $hosts };

  my @ret;

  for my $host (@hosts) {
    my $host_data = {};
    if($retrieve_host_data) {
      $host_data = $self->get_host_parameters(host => $host);
    }
    push @ret, Foreman::Server->new(foreman => $self, name => $host, %{ $host_data });
  }

  @ret;

}

sub get_host_parameters {
  my $self = shift;
  my ($host) = validated_list(
    \@_,
    host => { isa => 'Str' },
  );

  my $data           = $self->_request("api/hosts/$host");
  return {} if(!$data->{host}->{hostgroup_id}); # there is no group definition

  my $data_hostgroup = $self->get_hostgroup_parameters(hostgroup => $data->{host}->{hostgroup_id});


  my %host_data;

  for my $param (@{ $data->{host}->{parameters} }) {
    $host_data{$param->{parameter}->{name}} = $param->{parameter}->{value};
  }

  # return a merged hash.
  # host data has precedence.
  return {
    %{ $data_hostgroup },
    %host_data,
    host_parameter => \%host_data,
    group_parameter => $data_hostgroup,
  };
}

sub get_hostgroup_parameters {
  my $self = shift;
  my ($hostgroup) = validated_list(
    \@_,
    hostgroup => { isa => 'Str' }
  );

  my $data = $self->_request("api/hostgroups/$hostgroup");

  my $ret = {};

  for my $key (keys %{ $data->{hostgroup}->{parameters} }) {
    $ret->{$key} = $data->{hostgroup}->{parameters}->{$key};
  }

  return $ret;
}

sub get_environments {
  my $self = shift;
  my $data = $self->_request('api/environments');
  map { $_->{environment}->{name} } @{ $data };
}

sub get_roles {
  my $self = shift;
  my $data = $self->_request('api/puppetclasses', $self->_build_query_string(
    per_page => 9999)
  );
  return grep { m/^role_/ } keys %{ $data };
}

### Private:

sub _request {
  my ($self, $resource, $query_string) = @_;

  my $url = $self->url . $resource . "?" . ($query_string || "");
  my $ua = $self->ua;
  $ua->timeout(30);

  my $resp = $ua->get($url,
    Accept        => 'version=1,application/json',
    Authorization => "Basic " . encode_base64($self->user . ":" . $self->password));

  print Dumper($resp) if($ENV{DEBUG});

  my $from_cache = 0;
  if($resp->code == 500) {
    if(! -f $self->cache) {
      print Dumper $resp;
      die "Error reading cache file. Error in foreman communication.";
    }
    my $cache = retrieve $self->cache;
    if(exists $cache->{$url}) {
      return $cache->{$url};
    }
    else {
      confess "No cache entry for $url";
    }
  }
  elsif(!$resp->is_success) {
    confess "Error requesting information from foreman.";
  }

  my $ref;

  $ref = decode_json($resp->decoded_content);
  print Dumper($ref) if (exists $ENV{DEBUG});

  if($from_cache == 0) {
    my $cache = {};
    eval {
      $cache = retrieve $self->cache if(-f $self->cache);
      1;
    };
    $cache->{$url} = $ref;
    store $cache, $self->cache;
  }

  return $ref;
}

sub _build_query_string {
  my ($self, %option) = @_;

  my @url = ();

  for my $key (sort keys %option) {
    push @url, "$key=" . uri_escape($option{$key});
  }

  return join('&', @url);
}

1;

__END__

=pod

=head1 NAME

Foreman - Read host information out of Foreman.

With this module you can retrieve hosts and host parameter from Foreman. You can create dynamic groups out of these hosts.

=head1 SYNOPSIS

 use Foreman;
   
 my $foreman = Foreman->new(
   url      => "https://foreman.your-domain.tld",
   user     => "foreman-user",
   password => "foreman-password",
 );
    
 group frontends => $foreman->get_hosts(environment => "stage", service => "shop"); 

=head1 METHODS

=over 4

=item get_hosts(%query_options)

The I<get_hosts()> method will construct a search query with the given key => value parameters and send it to foreman. The returning data will be converted in an array. Every Array-Item is an object of the type I<Foreman::Server>. This object can just be passed on to the I<group()> function.

If you store the authentication settings inside Foreman you can modify these data inside the I<Foreman::Server> object so that Rex knows which login and password to use.

 my $foreman = Foreman->new(
   url      => "https://foreman.your-domain.tld",
   user     => "foreman-user",
   password => "foreman-password",
   modify_host_options => sub {
    my ($foreman, $server) = @_;
    $server->{auth}->{user}      = $server->{deploy_user};
    $server->{auth}->{password}  = decrypt($server->{deploy_password});
    $server->{auth}->{auth_type} = $server->{auth_type};
   },
 );
  
 
=item get_host(host => "hostname")

This method will return a single host object (I<Foreman::Server>).


=item get_environments()

This method will return all environments Foreman is aware of. It will return a list of names.

=item get_roles()

This method will return a list of roles Foreman knows (for example Puppet roles). In fact this method is querying Foreman for all known I<puppetclasses> and return the ones which start with I<role_>.


=item get_hostgroup_parameters(hostgroup => "hostgroup-name")

This method will return all parameters that are registered with a hostgroup.

=item get_host_parameters(host => "hostname")

This method will return all host parameters that are registered with a host. It will also merge the hostgroup parameters.

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

