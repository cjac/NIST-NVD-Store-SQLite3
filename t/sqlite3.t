#!perl -T

use strict;
use warnings;
use Test::More tests => 12;
use Data::Dumper;
use FindBin qw($Bin);

( my $test_dir ) = $Bin =~ m:^(.*?/t)$:;

( my $data_dir ) = "$test_dir/data"          =~ m:^(.*/data)$:;
( my $db_file )  = "$data_dir/nvdcve-1.1.db" =~ /^(.*db)$/;

BEGIN {
    use_ok('NIST::NVD::Store::SQLite3') || print "Bail out!";
}

my $sqlite3 = NIST::NVD::Store::SQLite3->new(
    store    => 'SQLite3',
    database => $db_file,
);

ok( $sqlite3, 'constructor returned goodness' );
isa_ok( $sqlite3, 'NIST::NVD::Store::SQLite3', '$sqlite' );
my $cpe_urn = 'cpe:2.3:a:bigantsoft:bigant_server:5.6.06:*:*:*:*:*:*:*';

my $cpe_pkey_id = $sqlite3->_get_cpe_id($cpe_urn);

ok( $cpe_pkey_id, 'return value is defined' );

like( $cpe_pkey_id, qr/\d+/, 'cpe primary key is numeric' );

my $cve = $sqlite3->get_cve_for_cpe( cpe => $cpe_urn );
ok( $cve, 'get_cve_for_cpe returned defined value (string)' );
isa_ok( $cve, 'ARRAY', '$cve' ) or diag Data::Dumper::Dumper($cve);
is( scalar @$cve, 7, 'cve list has correct number of elements (string)' );

$cve = $sqlite3->get_cve_for_cpe( cpe => $cpe_pkey_id );
ok( $cve, 'get_cve_for_cpe returned defined value (numeric)' );
isa_ok( $cve, 'ARRAY', '$cve' ) or diag Data::Dumper::Dumper($cve);
is( scalar @$cve, 7, 'cve list has correct number of elements (numeric)' );

is_deeply(
    $cve,
    [
     'CVE-2022-23345',
     'CVE-2022-23346',
     'CVE-2022-23347',
     'CVE-2022-23348',
     'CVE-2022-23349',
     'CVE-2022-23350',
     'CVE-2022-23352'
    ],
    'cve list contains the right elements'
) or diag Data::Dumper::Dumper($cve);

