#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'NIST::NVD::Store::BFDB' ) || print "Bail out!
";
}

diag( "Testing NIST::NVD::Store::BFDB $NIST::NVD::Store::BFDB::VERSION, Perl $], $^X" );
