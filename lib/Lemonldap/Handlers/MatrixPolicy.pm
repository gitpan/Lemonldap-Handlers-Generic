package Lemonldap::Handlers::MatrixPolicy;
use strict;
our ( @ISA, $VERSION, @EXPORTS );
$VERSION = '2.00';
our $VERSION_LEMONLDAP = "2.0";
our $VERSION_INTERNAL  = "2.0";
sub get                
{
    my $class=  shift;
    my %_param= @_;
    
my $self;
    my $config =$_param{parameters}->{'config'};
    my $session= $_param{'session'};
    unless ($session)  {
$self->{response} = 0; #0 time out 
bless $self,$class;
return $self;
    }

my $complement;   
my $dn = $session->{dn};
$dn=~ s/ //g;
    my $major = $config->{ATTRLDAP};
    my $minor = $config->{LDAPCONTROL};

  if  (exists($session->{$major}->{$minor}))  
{
    $complement =$session->{$major}->{$minor};
#### begin:  here for he compatibility  with older lemonldap
    $complement=~  s/#.*//;
###  end  :  here for he compatibility  with older lemonldap
}  ;
   
$self->{response} = 503  if  $config->{ALLOW}  eq 'DISABLED';

unless (defined $complement)  {
$complement = '_DENY_'; 
$self->{response} = 403; #403 = FORBIDDEN  200 = OK 
$complement =  '_ALLOW_' && $self->{response} = '_ALLOW_'  if  $config->{ALLOW}  eq 'ALL';
undef $complement if ($self->{response} == '403' or $self->{response} == '503' );
}
 undef $complement if ($self->{response} == '403' or $self->{response} == '503' );
$self->{profil} = $complement ;
bless $self,$class;
return $self;
}

1;

=pod

=for html <center> <H1> Lemonldap::Handlers::MatrixPolicy </H1></center> 


=head1 NAME

    Lemonldap::Handlers::MatrixPolicy  - Plugin  for Lemonldap sso system

=head1 DESCRIPTION

 MatrixPolicy is the default authorization manager  of lemonldap  websso framework .
 This module uses matrix (hash with two dimensions) in order to grant access or deny  on ressource.
 The first axial line is given by ATTRLDAP (or Majeur) the  second axial line is LDAPCONTROL (Mineur) parameter.
 

 
 see http://lemonldap.sf.net for more infos .
 

=head2 Overlay

If you wat use your own autorization method you must use PLUGINPOLICY parameter like this :
  in httpd.conf : perlsetvar lemonldappluginpolicy MyModule 

 Your module must accept  2 parameters : config (all the hash of config ) and session (all hash of session) 
 Your module must provide the 'get' method  and provide 'response' and 'profil' data object.

  response may content : 0  : no session (time out) 
                         403: deny access by rules
                         503: deny access for all (service not available) 
  profil may content : string of role 

=head1 SEE ALSO

Lemonldap(3), Lemonldap::Portal::Standard

http://lemonldap.sourceforge.net/

"Writing Apache Modules with Perl and C" by Lincoln Stein E<amp> Doug
MacEachern - O'REILLY

=over 1

=item Eric German, E<lt>germanlinux@yahoo.frE<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Isabelle Serre, E<lt>isabelle.serre@justice.gouv.frE<gt>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Eric German E<amp> Xavier Guimard E<amp> Isabelle Serre

Lemonldap originaly written by Eric german who decided to publish him in 2003
under the terms of the GNU General Public License version 2.

=over 1

=item This package is under the GNU General Public License, Version 2.

=item The primary copyright holder is Eric German.

=item Portions are copyrighted under the same license as Perl itself.

=item Portions are copyrighted by Doug MacEachern and Lincoln Stein.
This library is under the GNU General Public License, Version 2.

=item Portage under Apache2 is made with help of : Ali Pouya and 
Shervin Ahmadi (MINEFI/DGI) 

=back

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 dated June, 1991.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  A copy of the GNU General Public License is available in the source tree;
  if not, write to the Free Software Foundation, Inc.,
  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut

