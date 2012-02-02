#!perl -T

use strict;
use warnings;
use Test::More tests => 12;
use Test::File;
use File::MMagic;
use FindBin qw($Bin);
use NIST::NVD::Query;

( my $test_dir ) = $Bin =~ m:^(.*?/t)$:;

( my $data_dir ) = "$test_dir/data" =~ m:^(.*/data)$:;
( my $convert_script ) =
  "$test_dir/../blib/script/convert-nvdcve" =~ m:^(.*?/convert-nvdcve$):;
( my $source_file ) =
  "$data_dir/nvdcve-2.0-test.xml" =~ /^(.*nvdcve-2.0-test.xml)$/;
( my $db_file )      = "$data_dir/nvdcve-2.0.db"         =~ /^(.*db)$/;
( my $cpe_idx_file ) = "$data_dir/nvdcve-2.0.idx_cpe.db" =~ /^(.*db)$/;

undef $ENV{PATH};
undef $ENV{ENV};
undef $ENV{CDPATH};

unlink($db_file)      if -f $db_file;
unlink($cpe_idx_file) if -f $cpe_idx_file;

chdir($data_dir);

system("$convert_script $source_file");

is( $?, 0, 'conversion script returned cleanly' );
file_exists_ok( $db_file, 'database file exists' );
file_not_empty_ok( $db_file, 'database file not empty' );
file_readable_ok( $db_file, 'database file readable' );
file_writeable_ok( $db_file, 'database file writeable' );
file_not_executable_ok( $db_file, 'database file not executable' );

my $mm  = new File::MMagic;
my $res = $mm->checktype_filename($db_file);

my ( $type, $fh, $data ) = ('application/octet-stream');

is( $res, $type, "file is correct type: [$type]" ) or diag $res;

my (
    $dev,  $ino,   $mode,  $nlink, $uid,     $gid, $rdev,
    $size, $atime, $mtime, $ctime, $blksize, $blocks
) = stat($db_file);

my $nowish = time();

ok( $nowish - $mtime <= 1, '$mtime is close' )
  or diag "off by " . $nowish - $mtime;

open( $fh, q{<}, $db_file )
  or die "couldn't open file '$db_file': $!";

ok( $fh, 'opened database file for reading' );

$type = $mm->checktype_filehandle($fh);
is( $type, 'application/octet-stream',
    "file contents indicate correct type: [$type]" );

$fh->read( $data, 0x8564 );

$res = $mm->checktype_contents($data);

is( $type, 'application/octet-stream',
    "file contents indicate correct type: [$type]" );

use File::LibMagic;

my $flm = File::LibMagic->new();

$type = $flm->describe_filename($db_file);
is(
    $type,
    'SQLite 3.x database',
    "file contents indicate correct type: [$type]"
);

my $q;

$q = eval {
    NIST::NVD::Query->new(
        store    => 'SQLite3',
        database => $db_file,
    );
};
ok( !$@, "no error" ) or diag $@;

is( ref $q, 'NIST::NVD::Query',
    'constructor returned an object of correct class' );

chdir($test_dir);

