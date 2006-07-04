package Lemonldap::Handlers::MatrixPolicy;
use strict;
use warnings;
our $VERSION = '2.00';
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
   $dn =~ s/ //g;
   my $major = $config->{ORGANIZATION};
   if( !defined($major) ){
	$major = "authz_headers";
   }
   my $minor = lc($config->{APPLCODE});

   if  ( defined($major) && defined($minor) &&  exists($session->{$major}->{$minor}))  
   {
     $complement = $session->{$major}->{$minor};
     #### begin:  here for he compatibility  with older lemonldap
     $complement =~  s/#.*//;
     ###  end  :  here for he compatibility  with older lemonldap
     if ( defined($config->{REGEXPMATRIXPOLICY}) && $complement !~ $config->{REGEXPMATRIXPOLICY} ){
	undef $complement;	
     }else{
	$self->{response} = 200;
     }
   }  
   
   $self->{response} = 503  if  lc($config->{ALLOW})  eq 'disabled';

   unless (defined $complement)  {
   $complement = '_DENY_'; 
   $self->{response} = 403; #403 = FORBIDDEN  200 = OK 
   $complement =  '_ALLOW_' && $self->{response} = '_ALLOW_'  if  lc($config->{ALLOW})  eq 'all';
   undef $complement if ($self->{response} == '403' or $self->{response} == '503' );
   }
 
   undef $complement if ($self->{response} == '403' or $self->{response} == '503' );
   $self->{profil} = $complement ;
   bless $self,$class;
   return $self;
}

1;
