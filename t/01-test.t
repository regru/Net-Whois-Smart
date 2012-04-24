#!/usr/bin/perl -w
use strict;
use Test::More;
use POE;

# data for tests
my @domains = qw( 
    yahoo.com
    freshmeat.net
    freebsd.org
    reg.ru
    ns1.nameself.com.NS
);

my @domains_not_reg = qw(
    thereisnosuchdomain123.com
    thereisnosuchdomain453.ru
);

my @ips = qw( 87.242.73.95 );

my @registrars = ('REGRU-REG-RIPN');
my $server  = 'whois.ripn.net',

# start test
plan tests => @domains + @domains_not_reg + @ips + @registrars + 1;

use_ok('Net::Whois::Smart');
print "The following tests requires internet connection...\n";

check_result("domain", Net::Whois::Smart::whois( query  => \@domains));

check_result(
    "domain (not reged)",
    Net::Whois::Smart::whois( query  => \@domains_not_reg ),
);

check_result("IP", Net::Whois::Smart::whois( query  => \@ips ));

check_result(
    "registrar",
    Net::Whois::Smart::whois(
        query  => \@registrars,
        server => $server,
    )
);

sub check_result {
    my ($type)      = shift;
    my @full_result = @_;
    
    foreach my $result ( @full_result ) {
        my $query = $result->{query} if $result;
        my $message = "whois for $type ".$result->{query}." from ".$result->{server};

        if ($type eq 'domain') {
            $query =~ s/.NS$//i;
            ok( $result && !$result->{error} && $result->{whois} =~ /$query/i, $message );
        } elsif ($type eq "domain (not reged)") {
            ok( $result && $result->{error}, $message);
        } elsif ($type eq "IP") {
            ok( $result && !$result->{error} && $result->{whois}, $message);
        } elsif ($type eq "registrar") {            
            ok( $result && !$result->{error} && $result->{whois} =~ /$query/i, $message );
        }
    }
    undef;
}

