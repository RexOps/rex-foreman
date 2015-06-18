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

no warnings 'redefine';

has url      => (is => 'ro', isa => 'Str', required => 1);
has user     => (is => 'ro', isa => 'Str', required => 1);
has password => (is => 'ro', isa => 'Str', required => 1);
has ua       => (is => 'ro', default => sub { LWP::UserAgent->new; });

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

  my $hosts = $self->_request('api/hosts',
                search => $option
              );

  my @hosts = map { $_ = $_->{host}->{name} } @{ $hosts };

  my @ret;

  for my $host (@hosts) {
    my $host_data = $self->get_host_parameters(host => $host);
    push @ret, Foreman::Server->new(foreman => $self, name => $host, %{ $host_data });
  }

  @ret;
}

sub get_host {
  my $self = shift;
  my (%option) = validated_hash(
    \@_,
    host => { isa => 'Str' },
  );

  my $host_data = $self->get_host_parameters(host => $option{host});
  return Foreman::Server->new(name => $option{host}, %{ $host_data });
}

sub get_host_parameters {
  my $self = shift;
  my ($host) = validated_list(
    \@_,
    host => { isa => 'Str' },
  );

  my $data           = $self->_request("api/hosts/$host");
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
  my $data = $self->_request('api/puppetclasses',
    per_page => 9999
  );
  return grep { m/^role_/ } keys %{ $data };
}

### Private:

sub _request {
  my ($self, $resource, %option) = @_;

  my $type = 'json';

  if(exists $option{TYPE}) {
    $type = $option{TYPE};
    delete $option{TYPE};
  }

  my $url = $self->url . "$resource?" . $self->_build_query_string(%option);

  my $resp = $self->ua->get($url,
    Accept        => 'version=1,application/json',
    Authorization => "Basic " . encode_base64($self->user . ":" . $self->password));

  print Dumper($resp) if($ENV{DEBUG});

  if(!$resp->is_success) {
    confess "Error requesting information from foreman.";
  }

  if($type eq 'yaml') {
    return Load($resp->decoded_content);
  }

  my $ref = decode_json($resp->decoded_content);
  print Dumper($ref) if (exists $ENV{DEBUG});
  return $ref;
}

sub _build_query_string {
  my ($self, %option) = @_;

  my @url = ();

  for my $key (keys %option) {
    if(ref $option{$key} eq "HASH") {
      my @inner_value = ();
      for my $inner_key (keys %{ $option{$key} }) {
        push @inner_value, "$inner_key\%3D" . $option{$key}->{$inner_key};
      }

      push @url, $key . '=' . join('%26', @inner_value);
    }
    else {
      push @url, "$key=$option{$key}";
    }
  }

  return join('&', @url);
}


1;
