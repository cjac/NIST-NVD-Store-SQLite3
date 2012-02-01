use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'NIST::NVD::Store::SQLite3',
    AUTHOR              => q{C.J. Adams-Collier <cjac@f5.com>},
    VERSION_FROM        => 'lib/NIST/NVD/Store/SQLite3.pm',
    ABSTRACT_FROM       => 'lib/NIST/NVD/Store/SQLite3.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'NIST-NVD-Store-SQLite3-*' },
);
