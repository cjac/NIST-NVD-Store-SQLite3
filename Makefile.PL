use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME      => 'NIST::NVD::Store::SQLite3',
    AUTHOR    => q{C.J. Adams-Collier <cjac@f5.com>},
    EXE_FILES => ['bin/convert-nvdcve'],

    VERSION_FROM   => 'lib/NIST/NVD/Store/SQLite3.pm',
    ABSTRACT_FROM  => 'lib/NIST/NVD/Store/SQLite3.pm',
    LICENSE        => 'perl',
    PL_FILES       => {},
    BUILD_REQUIRES => {
        'File::MMagic'          => 0,
        'File::LibMagic'        => 0,
        'Test::More'            => 0,
        'Test::File'            => 0,
        'Test::Pod::Coverage'   => 0,
        'Test::Pod'             => 0,
        'Perl::Critic'          => 0,
        'XML::XPath'            => 0,
        'XML::XPath::XMLParser' => 0,
        'Perl::Critic'          => 0,
    },
    PREREQ_PM => {
        'Time::HiRes'  => 0,
        'Data::Dumper' => 0,
        Carp           => 0,
        DBI            => 0,
        Storable       => 0,
    },
    PREREQ_PM => {
        'Data::Dumper' => 0,
        Storable       => 0,
        'Time::HiRes'  => 0,
        Carp           => 0,
        DBI            => 0,
>>>>>>> d037d5cf9600e4025854acea3351725faee8231d
        'DBD::SQLite'  => 0,
        'NIST::NVD'    => 0.08,
    },
    dist  => { COMPRESS => 'bzip2 -9f', SUFFIX => 'bz2', },
    clean => { FILES    => 'NIST-NVD-Store-SQLite3-*' },
);
