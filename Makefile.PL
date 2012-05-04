use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::Whois::Smart',
    AUTHOR              => 'Sergey Kotenko <graykot@gmail.com>',
    VERSION_FROM        => 'lib/Net/Whois/Smart.pm',
    ABSTRACT_FROM       => 'lib/Net/Whois/Smart.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' 				=> 0,
	'POE::Component::Client::Whois::Smart'  => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-Whois-Smart-*' },
);
