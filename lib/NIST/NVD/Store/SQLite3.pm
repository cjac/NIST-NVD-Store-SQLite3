package NIST::NVD::Store::SQLite3;

use NIST::NVD::Store::Base;
use base qw{NIST::NVD::Store::Base};

use warnings;
use strict;

use Storable qw(nfreeze thaw);
use DBI;
use Time::HiRes qw( gettimeofday );

=head1 NAME

NIST::NVD::Store::SQLite3 - SQLite3 store for NIST::NVD

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

my %query = (
    cpe_create => qq{
CREATE TABLE IF NOT EXISTS cpe (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  urn     VARCHAR(64),

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
  cve_id  VARCHAR(16),
  cve_dump BLOB
)},
    cpe_cve_map_create => qq{
CREATE TABLE IF NOT EXISTS cpe_cve_map (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,

  cpe_id INTEGER,
  cve_id INTEGER
)},

    cve_for_cpe_select => qq{
SELECT cpe.urn,cve.cve_id
FROM cve,cpe,cpe_cve_map
WHERE cpe.urn=?
  and cpe.id=cpe_cve_map.cpe_id
  and cpe_cve_map.cve_id=cve.id
},

    get_cpe_id_select => qq{
SELECT id FROM cpe WHERE cpe.urn=?
},
    get_cve_id_select => qq{
SELECT id FROM cve WHERE cve.cve_id=?
},
    put_idx_cpe_insert => qq{
INSERT INTO cpe_cve_map (cpe_id,cve_id)
VALUES ( ?, ? )
},

    put_cve_insert => qq{
INSERT INTO cve ( cve_dump, cve_id ) VALUES (?, ?)
},

    put_cve_update => qq{
UPDATE cve SET cve_dump=? WHERE cve.id=?
},

    put_cpe_insert => qq{
INSERT INTO cpe ( urn,part,vendor,product,version,updt,edition,language )
VALUES( ?,?,?,?,?,?,?,? )
}

);

my %sth = ();

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use NIST::NVD::Store::SQLite3;

    my $NVD_Storage_SQLite3 = NIST::NVD::Store::SQLite3->new();
    ...

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
        qw( put_cpe_insert cve_for_cpe_select put_idx_cpe_insert
        put_cve_insert put_cve_update get_cpe_id_select get_cve_id_select )
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

    foreach my $statement (qw(cpe_create cve_create cpe_cve_map_create)) {

        my $query = $query{$statement};

        $sth{$statement} //= $dbh->prepare($query);
        $sth{$statement}->execute();
    }

    return $dbh;
}

=head2 get_cve_for_cpe

=cut

sub get_cve_for_cpe {
    my ( $self, $cpe ) = @_;

    $sth{cve_for_cpe_select}->execute($cpe);

    my $cve_id = [];

    while ( my $row = $sth{cve_for_cpe_select}->fetchrow_hashref() ) {

        #        print STDERR ( join( ",", keys %$row ), "\n" );
        push( @$cve_id, $row->{'cve.cve_id'} );
    }

    return $cve_id;
}

=head2 _get_cve_id

=cut

sub _get_cve_id {
    my ( $self, $cve_id ) = @_;

    return $self->{cve_map}->{$cve_id}
      if ( exists $self->{cve_map}->{$cve_id} );

    $sth{get_cve_id_select}->execute($cve_id);

    # TODO: Assert that this query returns zero or one result
    my $rows = 0;
    while ( my $row = $sth{get_cve_id_select}->fetchrow_hashref() ) {
        print STDERR "multiple results for value intended to be unique\n"
          if ( $rows++ );

        $self->{cve_map}->{$cve_id} = $row->{id};
    }

    return $self->{cve_map}->{$cve_id}
      if ( exists $self->{cve_map}->{$cve_id} );

    return;
}

=head2 _get_cpe_id

=cut

sub _get_cpe_id {
    my ( $self, $cpe_urn ) = @_;

    return $self->{cpe_map}->{$cpe_urn}
      if ( exists $self->{cpe_map}->{$cpe_urn} );

    $sth{get_cpe_id_select}->execute($cpe_urn);

    # TODO: Assert that this query only returns one result
    while ( my $row = $sth{get_cpe_id_select}->fetchrow_hashref() ) {
        print STDERR "multiple results for value intended to be unique\n";
        $self->{cpe_map}->{$cpe_urn} = $row->{id};
    }

    return $self->{cpe_map}->{$cpe_urn};
}

=head2 get_cve


=cut

sub get_cve {

}

=head2 put_idx_cpe


=cut

sub put_idx_cpe {
    my ( $self, $vuln_software ) = @_;

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");

    while ( my ( $cpe_urn, $cve_id ) = ( each %$vuln_software ) ) {
        $sth{put_idx_cpe_insert}->execute( $cpe_urn, $cve_id );
    }

    $self->{sqlite}->commit();
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

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");

    foreach my $urn ( keys %cpe_urn ) {
        my (
            $prefix,  $nada,   $part,    $vendor, $product,
            $version, $update, $edition, $language
        ) = split( m{[/:]}, $urn );

        $sth{put_cpe_insert}->execute(
            $urn,     $part,   $vendor,  $product,
            $version, $update, $edition, $language
        );
    }

    $self->{sqlite}->commit();
}

=head2 put_cve


=cut

sub put_cve {

}

=head2 put_nvd_entries


=cut

sub put_nvd_entries {
    my ( $self, $entries ) = @_;

    # TODO: Batch this.  Run a single $sth->execute() for all inserts,
    # and one for all updates.

    my $num_entries = int( keys %$entries );

    $self->{sqlite}->do("BEGIN IMMEDIATE TRANSACTION");

    while ( my ( $cve_id, $entry ) = ( each %$entries ) ) {
        my $frozen = nfreeze($entry);

        my $cve_pkey_id = $self->_get_cve_id($cve_id);

        my $sth;
        if ($cve_pkey_id) {
            $cve_id = $cve_pkey_id;
            $sth    = $sth{put_cve_update};
        }
        else {
            $sth = $sth{put_cve_insert};
        }

        $sth->execute( $entry, $cve_id );
        print STDERR ".";
    }

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

Copyright 2012 C.J. Adams-Collier.

This program is released under the following license: f5 internal


=cut

1;    # End of NIST::NVD::Store::SQLite3
