use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME      => 'NIST::NVD::Store::SQLite3',
    AUTHOR    => q{C.J. Adams-Collier <cjac@f5.com>},
    EXE_FILES => ['bin/convert-nvdcve'],

    VERSION_FROM  => 'lib/NIST/NVD/Store/SQLite3.pm',
    ABSTRACT_FROM => 'lib/NIST/NVD/Store/SQLite3.pm',
    LICENSE       => 'perl',
    PL_FILES      => {},
    PREREQ_PM     => {
        'Test::More'               => 0,
        'Test::File'               => 0,
        'XML::XPath'               => 0,
        Storable                   => 0,
        'DBD::SQLite'              => 0,
											'Time::HiRes' => 0,
											Carp => 0
    },
    dist  => { COMPRESS => 'bzip2 -9f', SUFFIX => 'bz2', },
    clean => { FILES    => 'NIST-NVD-Store-SQLite3-*' },
);
