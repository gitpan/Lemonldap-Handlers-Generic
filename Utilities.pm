package Lemonldap::Handlers::Utilities;
use Apache::Session::Memorycached;
use Apache::Constants qw(:common :response);
use BerkeleyDB;
use MIME::Base64;
use strict;
our ( @ISA, $VERSION, @EXPORTS );
$VERSION = '1.01';
our $VERSION_LEMONLDAP = "1.2";
our $VERSION_INTERNAL  = "0.03-4";
my %STACK;
sub cache3                
{
    my ($conf,$id) =@_;
my %config  =%$conf;
my $SERVERS = $config{SERVERS};

my %session ;

   tie %session, 'Apache::Session::Memorycached', $id,$SERVERS;
 unless ($session{dn}) {  ##  the cookie is present but i can't  retrieve session
                         ##  tree causes : Too many connection are served.              
                         ##                the server of session was restarted                
                         ##                It's time out                 
 
     untie %session ;
     return ('NULL','NULL');
# I say it's time out 
                    }
my $complement;   
my $dn = $session{dn};
$dn=~ s/ //g;
  if  (exists($session{$config{ATTRLDAP}}{$config{LDAPCONTROL}})) 
{
           $complement =$session{$config{ATTRLDAP}}{$config{LDAPCONTROL}};
#### begin:  here for he compatibility  with older lemonldap
            $complement=~  s/#.*//;
###  end  :  here for he compatibility  with older lemonldap
}  else {
untie %session;
return ('0',$dn); };
untie %session;
my $ligne_h;
if ($complement =~ /^uid/)  {
$ligne_h = $complement;


}  else 
{

$ligne_h = $dn;
if (defined($complement)) {
$ligne_h.=":$complement";
} 
}
return ($ligne_h,$dn);

}
sub goPortal {
    my  ($r,$conf,$op,$id) = @_;
     my $log=$r->log;
     my %CONFIG= %$conf;
        my $urlc_init = $CONFIG{BASEPUB}.$r->uri;
        $urlc_init.="?".$r->args if $r->args; 
       my  $urlc_initenc = encode_base64($urlc_init,"");
       	$r->header_out(location =>$CONFIG{PORTAL}."?op=$op&url=$urlc_initenc");
         $log->warn("$CONFIG{ID_HANDLER}: ERROR OF LOCKING  ON :$id") if ($op eq 't') ; 
        my $messagelog =  "$CONFIG{ID_HANDLER} : Redirect to portal (url was ".$urlc_init.")";
        $log->info($messagelog); 
	return REDIRECT;
        
}
sub cookie {
    my ($ligne, $co) =@_;

		if ($ligne=~ /$co/) {
		    $ligne=~ s/$co=(.+?)\b//;
		    $ligne=~ s/;\s+;/;/;
		    $ligne=~ s/^\s?;//;
		    $ligne=~ s/^\s+;//;
		}
    return $ligne;
}



sub cache2 {
    my ($conf,$id) =@_;
    my %CONFIG=%$conf;
my $message;
    my $ligne_h;
               tie %STACK, 'BerkeleyDB::Btree',
                         -Filename => $CONFIG{KEYIPC} ,
		         -Flags => DB_CREATE ;
   ;
	          $ligne_h = $STACK{$id} ;      
                    if  ($ligne_h) {  ## match in ipc 
			$message= "$CONFIG{ID_HANDLER} :  match in cache level 2 for $id";
                        untie %STACK;    
		    } else  { 
				       $message="$CONFIG{ID_HANDLER}: No match in cache level 2 for $id";}
    return ($ligne_h,$message);



}
sub   save_session {
my $id = shift;
my $trace = shift;
$STACK{$id} = $trace;
untie %STACK;
}

1;
