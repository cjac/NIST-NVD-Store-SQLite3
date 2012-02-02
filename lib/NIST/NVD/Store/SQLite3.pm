package NIST::NVD::Store::SQLite3;

use NIST::NVD::Store::Base;
use base qw{NIST::NVD::Store::Base};

use warnings;
use strict;

use DBI;



=head1 NAME

NIST::NVD::Store::SQLite3 - The great new NIST::NVD::Store::SQLite3!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

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

    my $fail = 0;

    return if $fail;

		return $self;
}

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

);

my %sth = ();

sub _connect_db {
    my ( $self, %args ) = @_;

    my $dbh = DBI->connect( "dbi:SQLite:dbname=$args{database}", "", "" );

		foreach my $statement ( qw(cpe_create cve_create cpe_cve_map_create) ){

			my $query = $query{$statement};

			$sth{$statement} //= $dbh->prepare($query);
			$sth{$statement}->execute();
		}

    return $dbh;
}

=head2 get_cve_for_cpe

=cut

sub get_cve_for_cpe {
	my( $self, $cpe ) = @_;

	$sth{cve_for_cpe_select} //= $self->{sqlite}->prepare($query{cve_for_cpe_select});

	$sth{cve_for_cpe_select}->execute( $cpe );

	
}

=head2 get_cve


=cut

sub get_cve {

}

=head2 put_idx_cpe


=cut

sub put_idx_cpe {

}

=head2 put_nvd_entries


=cut

sub put_nvd_entries {

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
