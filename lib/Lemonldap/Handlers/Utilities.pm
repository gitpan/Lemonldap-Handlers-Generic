package Lemonldap::Handlers::Utilities;
use Apache::Constants qw(:common :response);
use BerkeleyDB;
use MIME::Base64;
use strict;
our ( @ISA, $VERSION, @EXPORTS );
$VERSION = '2.00';
our $VERSION_LEMONLDAP = "2.0";
our $VERSION_INTERNAL  = "2.0";
my %STACK;
###########################################################
# cleanupcookie function  (config,cookie line)            #
# return $id storing in lemonldap cookie                  #
# and remove lemonldap cookie of header cookie            #
# if STOPCCOKIE is actived                                #
# Should return undef,undef wihtout $id and cookie        #
#                                                         #
###########################################################
sub  cleanupcookie {
(my $config,my $cookie_line)= @_;
return (undef,undef) unless $cookie_line ;
my  $local_cookie = $config->{'COOKIE'} ;
my @tab = split /;/, $cookie_line;
my @tmp ;
my $id;
foreach (@tab) {
    if (  /$local_cookie=([^; ]+)/ ) {
        push @tmp, $_   unless  ($config->{STOPCOOKIE}); 
        $id = $1;
        $id =~ s/\s//g;# remove  space 
          }  else { push @tmp, $_ ;} 
 }
my $ret ;

if  (@tmp) {   
 $ret = join ";",@tmp;

}
return ($id,$ret) ;
}

sub rewrite_cookie {
(my $cookie_line , my $config) = @_;
my  $local_domain = $config->{'DOMAIN'} ;
my @tab = split /;/, $cookie_line;
my @tmp ;
my $flag;
foreach  (@tab) {
    next if /path/ ;
#    $date = $_ if /expire/i;

(push @tmp,$_) and (next)  unless  /domain/ ;
(my $domain) = /domain\s?=\s?([^; ]+)/; 
 if ($domain=~ /$local_domain/i)  {
     push @tmp,$_ ;
}  else { 
    $flag=1;
   my  $l = 'domain = .'.$local_domain ;
   push @tmp, $l ; } 

}
my $ret = join ";",@tmp;
if ($flag) {
    return $ret ;
}  else { return $cookie_line ; }

}

sub cache2 {
    my ($path,$pid,$id) =@_;
    my $message;
    my $ligne_h;
               tie %STACK, 'BerkeleyDB::Btree',
                         -Filename => "$path/$pid.db" ,
		         -Flags => DB_CREATE ;
   ;
	          $ligne_h = $STACK{$id} ;      
                    if  ($ligne_h) {  ## match in ipc 
			$message= "match in cache level 2 for $id";
                        untie %STACK;    
		    } else  { 
				       $message="No match in cache level 2 for $id";}
    return ($ligne_h,$message);



}
sub goPortal {
    my  ($r,$conf,$op,$id) = @_;
     my $log=$r->log;
     my %CONFIG= %$conf;
        my $urlc_init = $CONFIG{BASEPUB}.$r->uri;
        $urlc_init.="?".$r->args if $r->args; 
       my  $urlc_initenc = encode_base64($urlc_init,"");
       	$r->headers_out->add(Location =>$CONFIG{PORTAL}."?op=$op&url=$urlc_initenc");
         $log->warn("$CONFIG{ID_HANDLER}: ERROR OF LOCKING  ON :$id") if ($op eq 't') ; 
        my $messagelog =  "$CONFIG{ID_HANDLER} : Redirect to portal (url was ".$urlc_init.")";
        $log->info($messagelog); 
	return REDIRECT;
        
}
sub   save_session {
my $id = shift;
my $trace = shift;
$STACK{$id} = $trace;
untie %STACK;
}

1;
