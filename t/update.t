#!perl -T

use strict;
use warnings;
use Test::More tests => 15;
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

my $cve_id_list;
my $cpe_urn = 'cpe:2.3:a:bigantsoft:bigant_server:5.6.06:*:*:*:*:*:*:*';

$cve_id_list = $q->cve_for_cpe( cpe => $cpe_urn );

is( ref $cve_id_list, 'ARRAY', 'cve_for_cpe returned ARRAY ref' );

is( int(@$cve_id_list), 7, 'correct number of CVEs returned for this CPE' );

foreach my $cve_entry (@$cve_id_list) {
    like( $cve_entry, qr{^CVE-\d{4,}-\d{4,}$}, 'format of CVE ID is correct' );
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

is( ref $entry, 'HASH', 'CVE entry is a HASH ref' );

my $baseMetricV3 = $entry->{impact}->{baseMetricV3};

is_deeply(
    $baseMetricV3,
          {
           'cvssV3' => {
                        'confidentialityImpact' => 'HIGH',
                        'version' => '3.1',
                        'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                        'userInteraction' => 'NONE',
                        'scope' => 'UNCHANGED',
                        'privilegesRequired' => 'NONE',
                        'baseScore' => '7.5',
                        'availabilityImpact' => 'NONE',
                        'attackComplexity' => 'LOW',
                        'integrityImpact' => 'NONE',
                        'attackVector' => 'NETWORK',
                        'baseSeverity' => 'HIGH'
                       },
           'exploitabilityScore' => '3.9',
           'impactScore' => '3.6'
          },
  'extracting baseMetricV3 worked'
) or diag Data::Dumper::Dumper $entry;
