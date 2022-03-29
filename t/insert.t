#!perl -T

use strict;
use warnings;
use Test::More tests => 18;
use FindBin qw($Bin);
use Data::Dumper;

( my $test_dir ) = $Bin =~ m:^(.*?/t)$:;

( my $data_dir ) = "$test_dir/data"          =~ m:^(.*/data)$:;
( my $db_file )  = "$data_dir/nvdcve-1.1.db" =~ /^(.*db)$/;

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

is(ref $q->{store}, 'NIST::NVD::Store::SQLite3',
   'storage class configured correctly')
  or diag('storage class: ['.ref( $q->{store} ).']');

my $cve_id_list;

my $cpe_urn = 'cpe:2.3:a:bigantsoft:bigant_server:5.6.06:*:*:*:*:*:*:*';

my $cpe_pkey_id = $q->{store}->_get_cpe_id($cpe_urn);
ok( $cpe_pkey_id, 'return value is defined' );

like( $cpe_pkey_id, qr/\d+/, 'cpe primary key is numeric' );

$cve_id_list = $q->cve_for_cpe( cpe => $cpe_urn );

is( ref $cve_id_list, 'ARRAY', 'cve_for_cpe returned ARRAY ref' );

is( int(@$cve_id_list), 7,
    "correct number of CVEs returned for this CPE: [$cpe_urn]" );

foreach my $cve_entry (@$cve_id_list) {
    like( $cve_entry, qr{^CVE-\d{4,}-\d{4,10}$}, 'format of CVE ID is correct' )
        or diag $cve_entry;
}

is_deeply(
    $cve_id_list,
    [
     'CVE-2022-23345',
     'CVE-2022-23346',
     'CVE-2022-23347',
     'CVE-2022-23348',
     'CVE-2022-23349',
     'CVE-2022-23350',
     'CVE-2022-23352'
    ],
    'Correct list of CVE IDs'
) or diag Data::Dumper::Dumper($cve_id_list);

my $entry = $q->cve( cve_id => $cve_id_list->[0] );

is( ref $entry, 'HASH', 'CVE entry is a HASH ref' )
    or diag Data::Dumper::Dumper($entry);

my $cvss = $entry->{'vuln:cvss'};

is_deeply(
    $cvss,
    {   'cvss:base_metrics' => {
            'cvss:confidentiality-impact' => 'NONE',
            'cvss:score'                  => '5.0',
            'cvss:authentication'         => 'NONE',
            'cvss:access-vector'          => 'NETWORK',
            'cvss:source'                 => 'http://nvd.nist.gov',
            'cvss:generated-on-datetime'  => '2011-12-08T10:11:00.000-05:00',
            'cvss:availability-impact'    => 'NONE',
            'cvss:integrity-impact'       => 'PARTIAL',
            'cvss:access-complexity'      => 'LOW'
            }

    },
    'extracting cvss worked'
) or diag Data::Dumper::Dumper($cvss);

