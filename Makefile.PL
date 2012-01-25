use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'NIST::NVD::Store::BFDB',
    AUTHOR              => q{C.J. Adams-Collier <cjac@f5.com>},
    VERSION_FROM        => 'lib/NIST/NVD/Store/BFDB.pm',
    ABSTRACT_FROM       => 'lib/NIST/NVD/Store/BFDB.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'f5 internal')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'NIST-NVD-Store-BFDB-*' },
);
