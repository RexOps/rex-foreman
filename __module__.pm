package Foreman;

use Moose;
use MooseX::Params::Validate;
use namespace::autoclean;
use Carp;

use LWP::UserAgent;
use JSON::XS;
use MIME::Base64;
use YAML;

use DM;
use DM::Helper;
use Rex -base;
use Rex::Group::Entry::Server;
use Data::Dumper;

no warnings 'redefine';

has url      => (is => 'ro', isa => 'Str', required => 1);
has user     => (is => 'ro', isa => 'Str', required => 1);
has password => (is => 'ro', isa => 'Str', required => 1);
has ua       => (is => 'ro', default => sub {
                    my $lwp_useragent_version = $LWP::UserAgent::VERSION;
                    my $ua;
                    if($lwp_useragent_version <= 6) {
                      $ua = LWP::UserAgent->new;
                    }
                    else {
                      $ua = LWP::UserAgent->new(ssl_opts => {verify_hostname => 0});
                    }
#                    $ua->env_proxy;
                    $ua;
                  });

sub get_hosts {
  my $self = shift;
  my (%option) = validated_hash(
    \@_,
    environment => { isa => 'Str' },
    service     => { isa => 'Str' },
  );

  my $hosts = $self->_request('api/hosts',
                search => {
                  environment => $option{environment},
                  class       => $option{service},
                }
              );

  my @hosts = map { $_ = $_->{host}->{name} } @{ $hosts };

  my @ret;

  for my $host (@hosts) {
    my $host_data = $self->get_host_parameters(host => $host);

    $host_data->{deploy_user_password} = decrypt_string($host_data->{deploy_user_password});

    copy_key deploy_user          => 'user'    , $host_data;
    copy_key deploy_user_password => 'password', $host_data;

    push @ret, Rex::Group::Entry::Server->new(name => $host, %{ $host_data });
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

  $host_data->{deploy_user_password} = decrypt_string($host_data->{deploy_user_password});

  copy_key deploy_user          => 'user'    , $host_data;
  copy_key deploy_user_password => 'password', $host_data;

  return Rex::Group::Entry::Server->new(name => $option{host}, %{ $host_data });
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
    if($param->{parameter}->{name} =~ m/\.enc$/) {
      my $new_key_name = $param->{parameter}->{name};
      $new_key_name =~ s/\.enc$//;
      $host_data{$new_key_name} = decrypt_string($param->{parameter}->{value});
    }
    else {
      $host_data{$param->{parameter}->{name}} = $param->{parameter}->{value};
    }
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
    if($key =~ m/\.enc$/) {
      my $new_key_name = $key;
      $new_key_name =~ s/\.enc$//;
      $ret->{$new_key_name} = decrypt_string($data->{hostgroup}->{parameters}->{$key});
    }
    else {
      $ret->{$key} = $data->{hostgroup}->{parameters}->{$key};
    }
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


# patch Rex::Group::Entry::Server
sub Rex::Group::Entry::Server::fact {
  my ($self, $fact) = @_;

  if( defined $fact && $self->{__puppet_fact__}->{$fact} ) {
    return $self->{__puppet_fact__}->{$fact};
  }

  # no fact found, run facter
  my $yaml = run "facter -y";
  $self->{__puppet_fact__} = Load($yaml);

  return $self->{__puppet_fact__}->{$fact};
}

1;
