package Net::Whois::Smart;

use warnings;
use strict;
use POE qw(Component::Client::Whois::Smart);

our $VERSION = '0.01';

our @result;

# get whois
sub whois {
    my %params = @_;
    @result = undef;
    my $query = delete $params{query};

    POE::Session->create(
	inline_states => {        
	    _start    => \&_start,
            _response =>\&_response,
	},
        args => [ $query, \%params ],
    );

    $poe_kernel->run();
    return @result;    
}

# POE session started
sub _start {
    my ($query, $params) = @_[ARG0, ARG1];
    delete $params->{event} if $params->{event};
    POE::Component::Client::Whois::Smart->whois(
        query => $query,
        %{$params},
        event => '_response',
    );
}

# got response
sub _response {
    @result = @{$_[ARG0]};
}

1;

__END__

=head1 NAME

Net::Whois::Smart - Very quick WHOIS-queries for list of domains, IPs or registrars.

=head1 SYNOPSIS

    use strict; 
    use warnings;
    use Net::Whois::Smart;

    my @queries = qw(
        google.com
        yandex.ru
        84.45.68.23
        REGRU-REG-RIPN        
    );

    my @all_results = Net::Whois::Smart(
        query    => \@queries,
        referral => 2,
    );
    
    foreach my $result ( @all_results ) {
        my $query = $result->{query} if $result;
        if ($result->{error}) {
            print "Can't resolve WHOIS-info for ".$result->{query}."\n";
        } else {
            print "QUERY: ".$result->{query}."\n";
            print "SERVER: ".$result->{server}."\n";
            print "WHOIS: ".$result->{whois}."\n\n";
        };
    }                            

=head1 DESCRIPTION

Net::Whois::Smart provides a very quick way to get WHOIS-info for list of domains, IPs or registrars.
Internally uses POE to run parallel non-blocking queries to whois-servers.
Supports recursive queries, cache, queries to HTTP-servers.

=head1 Functions

=over

=item whois()

whois( query [, params] )
Get whois-info for list of queries. One argument is required and some optional:

=back

=over 2

=item query

query is an arrayref of domains, ips or registaras to send to
whois server. Required.

=item server

Specify server to connect. Defaults try to be determined by the component. Optional.

=item referral

Optional.

0 - make just one query, do not follow if redirections can be done;

1 - follow redirections if possible, return last response from server; # default

2 - follow redirections if possible, return all responses;


Exapmle:
   
    my @all_results = Net::Whois::Smart::whois(
        query    => [ 'google.com', 'godaddy.com' ],
        referral => 2,
    );
    foreach my $result ( @all_results ) {
        my $query = $result->{query} if $result;
        if ($result->{error}) {
            print "Can't resolve WHOIS-info for ".$result->{query}."\n";
        } else {
            print "Query for: ".$result->{query}."\n";
            # process all subqueries
            my $count = scalar @{$result->{subqueries}};
            print "There were $count queries:\n";
            foreach my $subquery (@{$result->{subqueries}}) {
                print "\tTo server ".$subquery->{server}."\n";
                # print "\tQuery: ".$subquery->{query}."\n";
                # print "\tResponse:\n".$subquery->{whois}."\n";
            }
        }
    }                            

=item omit_msg

1 - attempt to strip several known copyright messages and disclaimers.

2 - will try some additional stripping rules if some are known for the spcific server.
Default is to give the whole response.

=item use_cnames

Use whois-servers.net to get the whois server name when possible.
Default is to use the hardcoded defaults.

=item timeout

Cancel the request if connection is not made within a specific number of seconds.
Default 30 sec.

=item local_ips

List of local IP addresses to use for WHOIS queries.
Addresses will be used used successively in the successive queries

=item cache_dir

Whois information will be cached in this directory. Default is no cache.

=cache_time

Number of minutes to save cache. Default 1 minute.

=head1 OUTPUT

ARG0 will be an array of hashrefs, which contains reply

#TODO: rewrite

=head1 AUTHOR

Sergey Kotenko <graykot@gmail.com>

This module is based on the Net::Whois::Raw L<http://search.cpan.org/perldoc?Net::Whois::Raw>
and POE::Component::Client::Whois L<http://search.cpan.org/perldoc?POE::Component::Client::Whois>

=head1 SEE ALSO

RFC 812 L<http://www.faqs.org/rfcs/rfc812.html>.