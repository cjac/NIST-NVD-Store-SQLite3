#!perl -T

use strict;
use warnings;
use Data::Dumper;
use Test::More tests => 16;
use FindBin qw($Bin);

( my $test_dir ) = $Bin =~ m:^(.*?/t)$:;

( my $data_dir ) = "$test_dir/data"          =~ m:^(.*/data)$:;
( my $db_file )  = "$data_dir/nvdcve-2.0.db" =~ /^(.*db)$/;

BEGIN {
    use_ok('NIST::NVD::Query') || print "Bail out!";
}

# Verify that each function returns expected result

my $q;

$q = eval {
    NIST::NVD::Query->new( store => 'SQLite3', database => $db_file, );
};

ok( !$@, "no error" ) or diag $@;

is( ref $q, 'NIST::NVD::Query',
    'constructor returned an object of correct class' );

my ( $cve_id_list, $cwe_id_list );

#my $cpe_urn = 'cpe:/a:microsoft:ie:7.0.5730.11';
my $cpe_urn = 'cpe:/a:apple:safari:4.0';

my $cpe_pkid = $q->{store}->_get_cpe_id($cpe_urn);

ok( $cpe_pkid, 'got PK ID for cpe urn' );

my $cve_id = $q->{store}->get_cve_for_cpe( cpe => $cpe_pkid );

my $query_ref = $q->{store}->_get_query();

my %result_count = (
    cve_for_cpe => 2,
    cwe_for_cpe => 42,
);

foreach my $method (qw{cve_for_cpe cwe_for_cpe}) {

    my $query_name = "${method}_select";

    ok( exists $query_ref->{$query_name}, "query [$query_name] exists" );

    my $query = $query_ref->{$query_name};

    ok( $query, "query [$query_name] is defined" ) or diag $query_name;

    my $sth = $q->{store}->_get_sth($query_name);

    $sth->execute($cpe_pkid);

    my @row;
    while ( my $row = $sth->fetchrow_hashref() ) {
        push( @row, $row );
    }

    ok( int(@row) != 0, 'direct query returned > 0 results' )
        or diag Data::Dumper::Dumper {
        query => $query_ref->{$query_name},
        id    => $cpe_pkid
        };

    my $object_list = $q->$method( cpe => $cpe_urn );

    is( ref $object_list, 'ARRAY', "[$method] returned ARRAY ref" )
        or diag $query;

    ok( int(@$object_list) > 0, "more than 0 results for method [$method]" )
        or diag "\$->$method( cpe => $cpe_urn )";
}

foreach my $cve_entry (@$cve_id_list) {
    like( $cve_entry, qr{^CVE-\d{4,}-\d{4}$}, 'format of CVE ID is correct' );
}

is_deeply(
    $cve_id_list,
    [ 'CVE-2002-2435', 'CVE-2010-5071' ],
    'Correct list of CVE IDs'
);

is_deeply(
    $cwe_id_list,
    [ 'CWE-2002-2435', 'CWE-2010-5071' ],
    'Correct list of CWE IDs'
);

my $entry = $q->cve( cve_id => $cve_id_list->[0] );

is( ref $entry, 'HASH', 'CVE entry is a HASH ref' );

my $cvss = $entry->{'vuln:cvss'};

is_deeply(
    $cvss,
    {   'cvss:base_metrics' => {
            'cvss:confidentiality-impact' => 'PARTIAL',
            'cvss:score'                  => '4.3',
            'cvss:authentication'         => 'NONE',
            'cvss:access-vector'          => 'NETWORK',
            'cvss:source'                 => 'http://nvd.nist.gov',
            'cvss:generated-on-datetime'  => '2011-12-08T06:47:00.000-05:00',
            'cvss:availability-impact'    => 'NONE',
            'cvss:integrity-impact'       => 'NONE',
            'cvss:access-complexity'      => 'MEDIUM'
        }
    },
    'extracting cvss worked'
);

