package NIST::NVD::Store::SQLite3;

use NIST::NVD::Store::Base;
use base qw{NIST::NVD::Store::Base};
use Carp;

use IO::Uncompress::Bunzip2 qw(bunzip2 $Bunzip2Error);
use IO::Compress::Bzip2 qw(bzip2 $Bzip2Error);

use warnings;
use strict;

use Storable qw(nfreeze thaw);
use DBI;
use Time::HiRes qw( gettimeofday );

=head1 NAME

NIST::NVD::Store::SQLite3 - SQLite3 store for NIST::NVD

=head1 VERSION

Version 0.03

=cut

our $VERSION = '0.03';

my %query = (
    cpe_create => qq{
CREATE TABLE IF NOT EXISTS cpe (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  urn     VARCHAR(64) CONSTRAINT uniq_urn UNIQUE ON CONFLICT FAIL,

  part     CHAR,
  vendor   VARCHAR(16),
  product  VARCHAR(16),
  version  VARCHAR(16),
  updt     VARCHAR(16),
  edition  VARCHAR(16),
  language VARCHAR(4)
)},
    cve_create => qq{
CREATE TABLE IF NOT EXISTS cve (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id  VARCHAR(16) CONSTRAINT uniq_cve_id UNIQUE ON CONFLICT FAIL,
  cve_dump BLOB
)},
    cwe_create => qq{
CREATE TABLE IF NOT EXISTS cwe (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  cwe_id  VARCHAR(16) CONSTRAINT uniq_cwe_id UNIQUE ON CONFLICT FAIL,
  cwe_dump BLOB
)},
    cpe_cve_map_create => qq{
CREATE TABLE IF NOT EXISTS cpe_cve_map (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,

  cpe_id INTEGER,
  cve_id INTEGER,
  CONSTRAINT uniq_cpe_cve UNIQUE ( cpe_id, cve_id ) ON CONFLICT IGNORE
)},
    cpe_cwe_map_create => qq{
CREATE TABLE IF NOT EXISTS cpe_cwe_map (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,

  cpe_id INTEGER,
  cwe_id INTEGER,
  CONSTRAINT uniq_cpe_cwe UNIQUE ( cpe_id, cwe_id ) ON CONFLICT IGNORE
)},
    cve_for_cpe_select => qq{
SELECT cve.cve_id
  FROM cpe_cve_map,cve
 WHERE cpe_cve_map.cpe_id=?
   AND cpe_cve_map.cve_id=cve.id
ORDER BY cve.cve_id
},
    cwe_for_cpe_select => qq{
SELECT cwe.cwe_id
  FROM cpe_cwe_map,cwe
 WHERE cpe_cwe_map.cpe_id=?
   AND cpe_cwe_map.cwe_id=cwe.id
ORDER BY cwe.cwe_id
},
    get_cpe_id_select => qq{
SELECT id FROM cpe WHERE cpe.urn=?
},
    get_cve_id_select => qq{
SELECT id FROM cve WHERE cve.cve_id=?
},
    get_cwe_id_select => qq{
SELECT id FROM cwe WHERE cwe.cwe_id=?
},
    get_cve_select => qq{
SELECT cve_dump FROM cve WHERE cve.cve_id=?
},
    get_cwe_select => qq{
SELECT cwe_dump FROM cwe WHERE cwe.cwe_id=?
},
    put_cve_idx_cpe_insert => qq{
INSERT INTO cpe_cve_map (cpe_id,cve_id)
VALUES ( ?, ? )
},
    put_cwe_idx_cpe_insert => qq{
INSERT INTO cpe_cwe_map (cpe_id,cwe_id)
VALUES ( ?, ? )
},
    put_cve_insert => qq{
INSERT INTO cve ( cve_dump, cve_id ) VALUES (?, ?)
},
    put_cve_update => qq{
UPDATE cve SET cve_dump=? WHERE cve.id=?
},
    put_cwe_insert => qq{
INSERT INTO cwe ( cwe_dump, cwe_id ) VALUES (?, ?)
},
    put_cwe_update => qq{
UPDATE cwe SET cwe_dump=? WHERE cwe.id=?
},
    put_cpe_insert => qq{
INSERT INTO cpe ( urn,part,vendor,product,version,updt,edition,language )
VALUES( ?,?,?,?,?,?,?,? )
}

);

my %sth = ();

=head1 SYNOPSIS

$q =
  eval { NIST::NVD::Query->new( store => 'SQLite3', database => $db_file, ); };


=head1 SUBROUTINES/METHODS

=head2 new

    my $NVD_Storage_SQLite3 = NIST::NVD::Store::SQLite3->new(
        store     => 'SQLite3',
        database  => '/path/to/database.sqlite',
    );

=cut

sub new {
    my ( $class, %args ) = @_;
    $class = ref $class || $class;

    my $self = bless { vuln_software => {} }, $class;

    $self->{sqlite} = $self->_connect_db( database => $args{database} );

    foreach my $statement (
        qw( put_cpe_insert
        cve_for_cpe_select cwe_for_cpe_select
        put_cve_idx_cpe_insert
        put_cwe_idx_cpe_insert
        put_cve_insert put_cve_update
        put_cwe_insert put_cwe_update
        get_cpe_id_select
        get_cve_id_select get_cve_select
        get_cwe_id_select get_cwe_select
        )
        )
    {
        $sth{$statement} = $self->{sqlite}->prepare( $query{$statement} );
    }
    my $fail = 0;

    return if $fail;

    return $self;
}

sub _connect_db {
    my ( $self, %args ) = @_;

    my $dbh = DBI->connect( "dbi:SQLite:dbname=$args{database}", "", "" );

    foreach my $statement (
        qw(cpe_create
        cve_create cpe_cve_map_create
        cwe_create cpe_cwe_map_create)
        )
    {

        my $query = $query{$statement};

        $sth{$statement} //= $dbh->prepare($query);
        $sth{$statement}->execute();
    }

    return $dbh;
}

=head2 get_cve_for_cpe

=cut

my $cpe_urn_re = qr{^(cpe:/(.)(:[^:]+){2,6})$};

sub get_cve_for_cpe {
    my ( $self, %args ) = @_;

    my $cpe = $args{cpe};

    return unless $cpe;

    my $cpe_pkey_id;
    if ( $cpe =~ /^\d+$/ ) {
        $cpe_pkey_id = $cpe;
    } else {
        ( my ( $cpe, @parts ) ) = ( $args{cpe} =~ $cpe_urn_re );
        $cpe_pkey_id = $self->_get_cpe_id($cpe);
    }

    $sth{cve_for_cpe_select}->execute($cpe_pkey_id);

    my $cve_id = [];

    while ( my $row = $sth{cve_for_cpe_select}->fetchrow_hashref() ) {
        push( @$cve_id, $row->{'cve_id'} );
    }

    return $cve_id;
}

=head2 get_cwe_for_cpe

=cut

sub get_cwe_for_cpe {
    my ( $self, %args ) = @_;

    my $cpe = $args{cpe};

    return unless $cpe;

    my $cpe_pkey_id;
    if ( $cpe =~ /^\d+$/ ) {
        $cpe_pkey_id = $cpe;
    } else {
        ( my ( $cpe, @parts ) ) = ( $args{cpe} =~ $cpe_urn_re );
        $cpe_pkey_id = $self->_get_cpe_id($cpe);
    }

    $sth{cwe_for_cpe_select}->execute($cpe_pkey_id);

    my $cwe_id = [];

    while ( my $row = $sth{cwe_for_cpe_select}->fetchrow_hashref() ) {
        push( @$cwe_id, $row->{'cwe_id'} );
    }

    return $cwe_id;
}

sub _get_cve_id {
    my ( $self, $cve_id ) = @_;

    return $self->{cve_map}->{$cve_id}
        if ( exists $self->{cve_map}->{$cve_id} );

    $sth{get_cve_id_select}->execute($cve_id);

    my $rows = 0;
    while ( my $row = $sth{get_cve_id_select}->fetchrow_hashref() ) {
        print STDERR
            "multiple ($rows) results for value intended to be unique.  cve_id: [$cve_id]\n"
            if ( $rows != 0 );

        $rows++;

        $self->{cve_map}->{$cve_id} = $row->{id};
    }

    return $self->{cve_map}->{$cve_id}
        if ( exists $self->{cve_map}->{$cve_id} );

    return;
}

sub _get_cwe_id {
    my ( $self, $cwe_id ) = @_;

    return $self->{cwe_map}->{$cwe_id}
        if ( exists $self->{cwe_map}->{$cwe_id} );

    $sth{get_cwe_id_select}->execute($cwe_id);

    my $rows = 0;
    while ( my $row = $sth{get_cwe_id_select}->fetchrow_hashref() ) {
        print STDERR
            "multiple ($rows) results for value intended to be unique.  cwe_id: [$cwe_id]\n"
            if ( $rows != 0 );

        $rows++;
        $self->{cwe_map}->{$cwe_id} = $row->{id};
    }

    return $self->{cwe_map}->{$cwe_id}
        if ( exists $self->{cwe_map}->{$cwe_id} );

    return;
}

sub _get_cpe_id {
    my ( $self, $cpe_urn ) = @_;

    return $self->{cpe_map}->{$cpe_urn}
        if ( exists $self->{cpe_map}->{$cpe_urn} );

    $sth{get_cpe_id_select}->execute($cpe_urn);

    # TODO: Assert that this query only returns one result
    my $rows = 0;
    while ( my $row = $sth{get_cpe_id_select}->fetchrow_hashref() ) {
        print STDERR
            "multiple ($rows) results for value intended to be unique.  cpe_urn: [$cpe_urn]\n"
            if ( $rows != 0 );
        $self->{cpe_map}->{$cpe_urn} = $row->{id};
    }

    return $self->{cpe_map}->{$cpe_urn};
}

sub _get_query {
    my ( $self, $query_name ) = @_;

    return $query{$query_name}
        if ($query_name);

    return %query if wantarray;

    return \%query;
}

sub _get_sth {
    my ( $self, $query_name ) = @_;

    return unless exists $query{$query_name};

    if ($query_name) {
        $sth{$query_name} //= $self->{sqlite}->prepare( $query{$query_name} );
        return $sth{$query_name};
    }

    return %sth if wantarray;

    return \%sth;
}

sub _prepare {

}

=head2 get_cve


=cut

sub get_cve {
    my ( $self, %args ) = @_;

    $sth{get_cve_select}->execute( $args{cve_id} );

    my $row = $sth{get_cve_select}->fetchrow_hashref();

    my $frozen = $row->{cve_dump};

    my $entry = eval { thaw $frozen };
    if (@$) {
        carp "Storable::thaw had a major malfunction.";
        return;
    }

    return $entry;
}

=head2 get_cwe


=cut

sub get_cwe {
    my ( $self, %args ) = @_;

    $sth{get_cwe_select}->execute( $args{cwe_id} );

    my $row = $sth{get_cwe_select}->fetchrow_hashref();

    my $frozen = $row->{cwe_dump};

    my $data = eval { thaw $frozen };
    if (@$) {
        carp "Storable::thaw had a major malfunction.";
        return;
    }

    return $data;
}


=head2 put_cve_idx_cpe

  my %vuln_software = ( $cpe_urn0 => [ $cve_id0,$cve_id42,... ],
                        $cpe_urn1 => [ $cve_id1,$cve_id24,... ],
  #                     ...,
                        $cpe_urnN => [ $cve_id2,$cve_id3,... ],
                       );
  $Updater->put_cve_idx_cpe( \%vuln_software );

=cut

my %uniq_cve_idx_cpe;

sub put_cve_idx_cpe {
    my ( $self, $vuln_software ) = @_;

    my @params;
    while ( my ( $cpe_urn, $cve_id ) = ( each %$vuln_software ) ) {
        my $cpe_pkey_id = $self->_get_cpe_id($cpe_urn);
        my (@cve_pkey_id) = map { $self->_get_cve_id($_) } @$cve_id;

        foreach my $cve_pkey_id (@cve_pkey_id) {
            next if $uniq_cve_idx_cpe{$cpe_pkey_id}->{$cve_pkey_id}++;
            push( @params, [ $cpe_pkey_id, $cve_pkey_id ] );
        }
    }

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");
    $sth{put_cve_idx_cpe_insert}->execute(@$_) foreach (@params);
    $self->{sqlite}->commit();
    return;
}

=head2 put_cwe_idx_cpe

  my %vuln_software = ( $cpe_urn0 => [ $cwe_id0,$cwe_id42,... ],
                        $cpe_urn1 => [ $cwe_id1,$cwe_id24,... ],
  #                     ...,
                        $cpe_urnN => [ $cwe_id2,$cwe_id3,... ],
                       );
  $Updater->put_cwe_idx_cpe( \%weaknesses );

=cut

my %uniq_cwe_idx_cpe;

sub put_cwe_idx_cpe {
    my ( $self, $weaknesses ) = @_;

    my (%cpe_pkey_id)
        = map { $_ => $self->_get_cpe_id($_) } keys %$weaknesses;

    my @params;
    while ( my ( $cpe_urn, $cwe_id ) = ( each %$weaknesses ) ) {
        my $cpe_pkey_id = $cpe_pkey_id{$cpe_urn};

        foreach my $id (@$cwe_id) {
            my ($digits) = ( $id =~ /(\d+)$/ );
            my $cwe_pkey_id = $self->_get_cwe_id($digits);

            unless ($cwe_pkey_id) {
                print STDERR "no data for [$id]\n";
                next;
            }

            next if $uniq_cwe_idx_cpe{$cpe_pkey_id}->{$cwe_pkey_id}++;
            push( @params, [ $cpe_pkey_id, $cwe_pkey_id ] );
        }
    }

    printf STDERR 'there are %i unique CPE URNs.' . "\n",
        int( keys %$weaknesses );

    printf STDERR 'inserting %i rows' . "\n", int(@params);

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");
    $sth{put_cwe_idx_cpe_insert}->execute(@$_) foreach (@params);
    $self->{sqlite}->commit();
    return;
}

=head2 put_cpe


=cut

my %inserted_cpe;

sub put_cpe {
    my ( $self, $cpe_urn ) = @_;

    $cpe_urn = [$cpe_urn] unless ( ref $cpe_urn eq 'ARRAY' );

    my %cpe_urn = map { $_ => 1 } @$cpe_urn;
    my $query   = 'SELECT id,urn FROM cpe';
    my $sth     = $self->{sqlite}->prepare($query);

    while ( my $row = $sth->fetchrow_hashref() ) {
        delete $cpe_urn{ $row->{cpe_urn} }
            if exists $cpe_urn{ $row->{cpe_urn} };
    }

    my @params;
    foreach my $urn ( keys %cpe_urn ) {
        next if $inserted_cpe{$urn}++;

        my ($prefix,  $nada,   $part,    $vendor, $product,
            $version, $update, $edition, $language
        ) = split( m{[/:]}, $urn );

        push(
            @params,
            [   $urn,     $part,   $vendor,  $product,
                $version, $update, $edition, $language
            ]
        );
    }

    $self->{sqlite}->do('BEGIN IMMEDIATE TRANSACTION');
    $sth{put_cpe_insert}->execute(@$_) foreach @params;
    $self->{sqlite}->commit();
}

=head2 put_cve


=cut

sub put_cve {

}

=head2 put_cwe


=cut

sub put_cwe {

}

=head2 put_nvd_entries


=cut

sub put_nvd_entries {
    my ( $self, $entries ) = @_;

    my %cve_pkey_id = map { $_ => $self->_get_cve_id($_) } keys %$entries;

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");

    while ( my ( $cve_id, $entry ) = ( each %$entries ) ) {
        my $frozen = nfreeze($entry);

        my $sth;
        if ( $cve_pkey_id{$cve_id} ) {
            $cve_id = $cve_pkey_id{$cve_id};
            $sth    = $sth{put_cve_update};
        } else {
            $sth = $sth{put_cve_insert};
        }

        $sth->execute( $frozen, $cve_id );
        print STDERR ".";
    }

    $self->{sqlite}->commit();
}

=head2 put_cwe_data


=cut

sub put_cwe_data {
    my ( $self, $weakness_data ) = @_;

    my @insert_entries;
    my @update_entries;

    my $insert_sth = $sth{put_cwe_insert};
    my $update_sth = $sth{put_cwe_update};

    foreach my $element (qw(View Category Weakness Compound_Element)) {
        my $data = $weakness_data->{$element};
        my %cwe_pkey_id;
        foreach my $k ( keys %$data ) {
            $cwe_pkey_id{$k} = $self->_get_cwe_id($k);
        }

        while ( my ( $cwe_id, $entry ) = ( each %$data ) ) {
            my $frozen = nfreeze($entry);

            if ( $cwe_pkey_id{$cwe_id} ) {
                $cwe_id = $cwe_pkey_id{$cwe_id};
                push( @update_entries, [ $frozen, $cwe_id ] );
            } else {
                push( @insert_entries, [ $frozen, $cwe_id ] );
            }
            print STDERR ".";
        }
    }

    printf STDERR "inserting \%i rows\n", int(@insert_entries);
    printf STDERR "updating \%i rows\n",  int(@update_entries);

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");
    $insert_sth->execute(@$_) foreach @insert_entries;
    $update_sth->execute(@$_) foreach @update_entries;
    $self->{sqlite}->commit();

}

=head1 AUTHOR

C.J. Adams-Collier, C<< <cjac at f5.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-nist-nvd-store-sqlite3 at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=NIST-NVD-Store-SQLite3>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc NIST::NVD::Store::SQLite3


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=NIST-NVD-Store-SQLite3>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/NIST-NVD-Store-SQLite3>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/NIST-NVD-Store-SQLite3>

=item * Search CPAN

L<http://search.cpan.org/dist/NIST-NVD-Store-SQLite3/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 F5 Networks, Inc.

This program is released under the following license: perl


=cut

1;    # End of NIST::NVD::Store::SQLite3
