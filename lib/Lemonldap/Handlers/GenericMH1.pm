package Lemonldap::Handlers::GenericMH1;
####  handler generic for lemonldap SSo system managing the MultiHoming
use strict;
#use warnings;
#####  use ######
use Apache();
use Apache::URI();
use Apache::Constants qw(:common :response);
use Apache::Session::Memorycached;
#use Apache::ModuleConfig;
use BerkeleyDB;
use MIME::Base64;
use LWP::UserAgent;
use Lemonldap::Config::Parameters;
use String::CRC32;
use Apache::Log();
#print STDERR "je passe phase 0\n";

#### common declaration #######
our (@ISA, $VERSION, @EXPORTS);
$VERSION = '0.15';
our $VERSION_LEMONLDAP="1.1" ;
our $VERSION_INTERNAL="0.1" ;

####
####
#### my declaration #########
our $UA;
our $DEBUG;
our $ID_HANDLER;
our $CONF;
our $PROXY;
our $KEYIPC;
our $IPCNB;
our $LDAPCONTROL;
our $DISABLEDCONTROL;
our $ATTRLDAP; 
our $COOKIE;
our $PORTAL;
our $BASEPUB;
our $GLUE;
our $BASEPRIV;
our $SERVERS;
our $CACHE;
our $CLIENT;
our %STACK;
our $PROXYEXT;
our $DOMAIN;
our $FILE;
our $STOPCOOKIE;
our $RECURSIF;
our $CACHE1_ENTETE;
our $GENERAL;
our $ID_HANDLER_IN_PROCESS;
our $NOM=  __PACKAGE__ ;
our $MULTIHOMINGLINE;
our  @TABLEMH ;
our $CONTROLSAVE;
our %HASHMH;
our $ANONYMOUSFUNC;
our $MOTIFIN;
our $MOTIFOUT;
our $MHURI_PREC;
our $MHURI;
#############################
@ISA = qw(LWP::UserAgent );
#if($ENV{MOD_PERL}) {
#	push @ISA, 'Dynaloader';
#	__PACKAGE__->bootstrap($VERSION);
#			}
#Apache->push_handlers( PerlChildInitHandler=>\&childInit );

###############################
##
##
#our ($VERSION, @EXPORTS);



sub handler {
	my $r=shift;
# log initilization
	my $log= $r->log;
	my $messagelog;
#### retrieve directive and build variables
#### but I 'll try it one time 
# I must know if the handler is call in the same  virtualhost ou contener
#
#
### I will try  retieve ID_HANDLER from  httpd conf 
$ID_HANDLER = $r->dir_config('LemonldapHandlerId');
      if  ($ID_HANDLER) {
     $messagelog = "$NOM Phase : handler initialization LOAD ID_HANDLER httpd.conf:$ID_HANDLER : succeded"; 
  } else { 
# I don't find anything for this handler in order to make link with XLM conf section
     $messagelog = "$NOM: Phase : handler initialization LOAD ID_HANDLER httpd.conf:failed"; 
 } 
	$log->debug($messagelog) ;

############################################

	unless ($ID_HANDLER eq $ID_HANDLER_IN_PROCESS ) {
## It doesn t be in the same context ; 
            undef  @TABLEMH;
            undef $ANONYMOUSFUNC;
            undef $CONTROLSAVE;
      	    undef $LDAPCONTROL;
            undef $CLIENT;
	    undef %HASHMH;
            undef     $MHURI_PREC;
            undef     $MHURI;
	}
## now I save the context of handler
	$ID_HANDLER_IN_PROCESS =$ID_HANDLER;
if ($MULTIHOMINGLINE) {  
$log->debug("$ID_HANDLER: Phase : handler initialization one step beyond") ; 
}

unless ($MULTIHOMINGLINE) {

$log->debug ("$ID_HANDLER: Phase : handler initialization LOAD XML file from  httpd.conf"); 

### I will try  retieve XML  from  httpd conf 
$FILE = $r->dir_config('LemonldapConfig');
$GLUE = $r->dir_config('LemonldapConfigIpcKey');
$log->debug("$ID_HANDLER: Phase : handler initialization LOAD XML file $FILE and $GLUE from  httpd.conf");
### retrieve domain xml 
$log->debug ("$ID_HANDLER: Phase : handler initialization LOAD DOMAIN  httpd.conf"); 
### I will try  retieve domain  from  httpd conf 

$DOMAIN = $r->dir_config('LemonldapDomain');
####
$log->debug( "$ID_HANDLER: Phase : handler initialization LOAD ID_HANDLER httpd.conf"); 
### I will try  retieve ID_HANDLER from  httpd conf 
$log-> debug("$ID_HANDLER: Phase : handler initialization try to load XML conf"); 

$CONF= Lemonldap::Config::Parameters->new (
                                                file => $FILE ,
					      cache => $GLUE );
	if ($CONF) {
$log->debug("$ID_HANDLER: Phase : handler initialization LOAD XML conf :succeded"); 
} else {
$log->debug("$ID_HANDLER: Phase : handler initialization LOAD XML conf : failed"); 
}


### here conf from XML is ready 
$log->debug("$ID_HANDLER: Phase : handler initialization LOAD XML conf"); 

### I'll search XML section from ID_HANDLER

if ($ID_HANDLER) {
    my $tmpconf;
$log->debug("$ID_HANDLER: domain matched $DOMAIN"); 

    if ($DOMAIN) {  
    	$GENERAL = $CONF->getDomain($DOMAIN) ;
	my $tmpconf = $GENERAL->{handler}->{$ID_HANDLER}; 
	$COOKIE = $GENERAL->{Cookie};
        $PORTAL=$GENERAL->{Portal};
        $CACHE =$GENERAL->{Session} ;
       parseConfig($tmpconf);
    		}  else 		{ 
	$tmpconf= $CONF->{$ID_HANDLER} ;
        parseConfig($tmpconf); 
			}
	} 

#now I read httpd.conf in order to  overlay the XML config 
#
#
#
#



}
### I 'll do this only once
unless ($CONTROLSAVE) {
####################################################
my $_proxy = $r->dir_config('LemonldapEnabledproxy');
$PROXY= $_proxy if $_proxy;
####################################################
#my $_keyIPC= $r->dir_config('LemonldapIpcKey');
#$KEYIPC= $_keyIPC if $_keyIPC;
####################################################
#my $_IPCNB= $r->dir_config('LemonldapIpcNb');
#$IPCNB= $_IPCNB if $_IPCNB;
####################################################
#my $_attrldap= $r->dir_config('LemonldapAttrLdap');
#$ATTRLDAP= $_attrldap if $_attrldap;
####################################################
#my $_ldapcontrol= $r->dir_config('LemonldapCodeAppli');
#$LDAPCONTROL=$_ldapcontrol  if $_ldapcontrol;
####################################################
#my $_disabledcontrol= $r->dir_config('LemonldapDisabled');
#$DISABLEDCONTROL=$_disabledcontrol  if $_disabledcontrol;
####################################################
my $_cache= $r->dir_config('LemonldapSession');
$CACHE=$_cache  if $_cache;
####################################################
my $_stop= $r->dir_config('LemonldapStopCookie');
$STOPCOOKIE=$_stop  if $_stop;
####################################################
my $_mode= $r->dir_config('LemonldapRecursive');
$RECURSIF=$_mode  if $_mode;
####################################################
my $_proxyext= $r->dir_config('LemonldapProxyExt');
$PROXYEXT=$_proxyext  if $_proxyext;
####################################################
my $_multihomingline= $r->dir_config('LemonldapMultiHoming');
$MULTIHOMINGLINE=$_multihomingline  if $_multihomingline;
####################################################

#
#
#
# Result 

    

$log->info("$ID_HANDLER: Phase : handler initialization VARIABLES PROXY           => $PROXY KEYIPC          => $KEYIPC IPCNB           => $IPCNB ATTRLDAP        => $ATTRLDAP LDAPCONTROL     => $LDAPCONTROL DISABLEDCONTROL => $DISABLEDCONTROL RECURSIF        => $RECURSIF PROXYEXT        => $PROXYEXT MULTI             => $MULTIHOMINGLINE STOPCOOKIE      => $STOPCOOKIE"); 
}


##############################  LOADER OF REGEXP #################
my $liste = $MULTIHOMINGLINE ;
my $control = crc32($liste);
if (($control != $CONTROLSAVE) or (!@TABLEMH ) )    { # le crc is different I must rebuild my anonymous sub 
my @lmh= split "," ,$liste;
@TABLEMH=();
%HASHMH =();
foreach (@lmh) {
my $clmh = $GENERAL->{handler}->{$_};
my $motifIN = $clmh->{'MotifIn'};
my $motifOUT = $clmh->{'MotifOut'};
my $base=$clmh->{BasePriv};
my  $proxy= $clmh->{Enabledproxy};
my  $keyipc=$clmh->{IpcKey};
my    $ipcnb= $clmh->{IpcNb};
my    $attrldap= $clmh->{AttrLdap};
my    $ldapcontrol=$clmh->{CodeAppli};
my  $disabledcontrol=$clmh->{Disabled};
my    $stopcookie= $clmh->{StopCookie};
my   $proxyext = $clmh->{ProxyExt};
my   $recursif= $clmh->{Recursive};           

my $s = { 'HANDLER'  => $_ ,
          'MOTIFIN' => $motifIN ,
          'MOTIFOUT' => $motifOUT ,
          'BASEPRIV' => $base,
          'ENABLEDPROXY' => $proxy,
          'KEYIPC' => $keyipc,
          'IPCNB' => $ipcnb,
          'ATTRLDAP' => $attrldap,
          'LDAPCONTROL' => $ldapcontrol,
          'DISABLEDCONTROL' => $disabledcontrol,
          'STOPCOOKIE' => $stopcookie,
          'PROXYEXT' => $proxyext,
          'RECURSIF' => $recursif,
         };   
   
$HASHMH{$_} = $s;
push @TABLEMH,  $s ;
}
$log->debug ("$ID_HANDLER: Phase : RELOADING MULTIHOST TABLE"); 
#now I buil the function 
my $sub = get_match_sub(\@TABLEMH);;
$log->debug ("$ID_HANDLER: Phase : MULTIHOMING TABLE  LOADED : $sub");

$ANONYMOUSFUNC =eval  $sub ;
$CONTROLSAVE=crc32($MULTIHOMINGLINE);


}


##### end of initialization 
## deleted those line  
my $uri =$r->uri;
	$log->info ("$ID_HANDLER :uri  requested: $uri");
##### end deleted lines 
	$MHURI = $ANONYMOUSFUNC->($uri);
# Stop  process  if no multihosting
if (($MHURI ==1) || (!($MHURI))) { 
    $log->warn ("$ID_HANDLER :multihoming failed for  $uri") ;

    return DECLINED  ;
}

	$log->notice ("$ID_HANDLER :multihoming actived for  $MHURI");
#now I must orverlaying info from config for this location 
###
	my $configm = $HASHMH{$MHURI};
	$BASEPRIV= $configm->{'BASEPRIV'};
        $PROXY  = $configm->{'ENABLEDPROXY'} if $configm->{'ENABLEDPROXY'} ;
	$ATTRLDAP =$configm->{'ATTRLDAP'};
	$IPCNB =$configm->{'IPCNB'};
	$KEYIPC= $configm->{'KEYIPC'};
	$LDAPCONTROL =$configm->{'LDAPCONTROL'};
	$DISABLEDCONTROL =$configm->{'DISABLEDCONTROL'};
	$STOPCOOKIE =$configm->{'STOPCOOKIE'};
	$RECURSIF=$configm->{'RECURSIF'};
	$PROXYEXT= $configm->{'PROXYEXT'} if $configm->{'PROXYEXT'}; 
        $MOTIFIN= $configm->{'MOTIFIN'};
	$MOTIFOUT=$configm->{'MOTIFOUT'};

if ($KEYIPC) {
	    $KEYIPC .="-$$";

    }

$log->debug( "$ID_HANDLER: Phase : handler initialization  LOCATION VARIABLES $MHURI LOCATION        => $MHURI PROXY           => $PROXY KEYIPC          => $KEYIPC IPCNB           => $IPCNB ATTRLDAP        => $ATTRLDAP LDAPCONTROL     => $LDAPCONTROL DISABLEDCONTROL => $DISABLEDCONTROL RECURSIF        => $RECURSIF PROXYEXT        => $PROXYEXT BASEPRIV        => $BASEPRIV MOTIFIN         => $MOTIFIN MOTIFOUT         => $MOTIFOUT STOPCOOKIE      => $STOPCOOKIE");

###
###
###
# for testing 
#return DECLINED;
## Log from MHURI 
if ($MHURI ne $MHURI_PREC)
{
    undef $CLIENT;


}
$MHURI_PREC = $MHURI ;

	if($PROXY){
$UA = __PACKAGE__->new;
$UA->agent(join "/", __PACKAGE__, $VERSION);
      $log->info ("$ID_HANDLER/$MHURI:  Build-in proxy actived") ;
	
             $r->handler("perl-script");
        $r->push_handlers( PerlHandler => \&proxy_handler );
	}
# Stop  process  if protection is disabled
	return DECLINED if  ($DISABLEDCONTROL);
#	return DECLINED unless ($PROXY);
# is this area protected
# configuration check
#unless ($COOKIE) {
####################################################
my $_cookie = $r->dir_config('LemonldapCookie');
$COOKIE= $_cookie if $_cookie;
####################################################
my $_basepub= $r->dir_config('LemonldapBasePub');
$BASEPUB=$_basepub  if $_basepub;
####################################################
#my $_basepriv= $r->dir_config('LemonldapBasePriv');
#$BASEPRIV=$_basepriv  if $_basepriv;
####################################################
my $_portal= $r->dir_config('LemonldapPortal');
$PORTAL=$_portal  if $_portal;
####################################################
####
##
##

$log->debug( "$ID_HANDLER/$MHURI: Phase : handler AUTHORIZATION VARIABLES
COOKIE   => $COOKIE
BASEPUB  => $BASEPUB
BASEPRIV => $BASEPRIV
PORTAL   => $PORTAL");

#}
#### Read cache info from  XML config 
# 
#
	unless ($SERVERS) {
my $xmlsession= $CONF->findParagraph('session',$CACHE);
$SERVERS = $CONF->formateLineHash ($xmlsession->{SessionParams});
$log->debug("$ID_HANDLER/$MHURI: Phase : handler AUTHORIZATION CACHE CONFIG: $SERVERS"); 

}
#
#

	# AUTHENTICATION
	# cookie search
	my %entete =$r->headers_in();
	my $idx =$entete{'Cookie'} ;
	# Load id value from cookie
#	$idx =~ /$COOKIE=([^; ]+)(;?)/o; 
# I remove the o option : o parse one time the regexp.
	$idx =~ /$COOKIE=([^; ]+)(;?)/;
	my $id =$1;
  #     $id='675314908c539c2c775072227c7b5d69';
  #      $id='c167b67d628deb1dcfe09de7aa7f927e';
	unless ($id) {
		# No cookie found: redirect to portal
	    $messagelog="$ID_HANDLER/$MHURI : No cookie found for ".$r->uri;
            $log->info($messagelog);
		return goPortal($r,'c');
	}
 $log->info("$ID_HANDLER/$MHURI: id session : $id<--->$idx");

	# SESSIONS CACHE 

#cache  level 1 test 
	my $ligne_h;
 unless ($id eq $CLIENT) {
            # Level 2 test by IPC 
     $log->info ("$ID_HANDLER/$MHURI: No match in cache level 1 for $id");
                    if ($IPCNB)  {  ####  We want use IPC                 
      		  $log->info("$ID_HANDLER/$MHURI :  search in cache level 2 for $id");
             tie %STACK, 'BerkeleyDB::Btree',
                            -Filename => $KEYIPC ,
	                                -Flags => DB_CREATE ;


                 $ligne_h = $STACK{$id} ;      
                    if  ($ligne_h) {  ## match in ipc 
			$log->info  ("$ID_HANDLER/$MHURI :  match in cache level 2 for $id");
			# expire_session($id) ;# put on the top of stack    
                                   } else  { 
				       $log->info("$ID_HANDLER/$MHURI: No match in cache level 2 for $id");
 }


## end no match in ipc
	                   }  ####  We want use IPC 

            unless ($ligne_h) { # no match in cache level 1 and 2 
	       $log->info ("$ID_HANDLER/$MHURI :  Search  in cache level 3 for $id");

###### 
######
######   search in backend cache 
######
		my %session ;
   tie %session, 'Apache::Session::Memorycached', $id,$SERVERS;
 unless ($session{dn}) {  ##  the cookie is present but i can't  retrieve session
                         ##  tree causes : Too many connection are served.              
                         ##                the server of session was restarted                
                         ##                It's time out                 
       
           $log->warning("$ID_HANDLER/$MHURI: ERROR OF LOCKING  ON :$id"); 
# I say it's time out 
	return goPortal($r,'t');
                       }
#here  we are retrieve session        
           $log->info ("$ID_HANDLER/$MHURI: SESSION FIND FOR:$id"); 
         #now we will look at authorization  and build an header and stock it for the next access
#FIRST : authorization 
my $uid = $session{uid};
$uid=~ s/ //g;
my $cn = $session{cn};
my $mail = $session{mail};
my $fonction = $session{fonction};
my $codique =$session{codique};
my $dn = $session{dn};
$dn=~ s/ //g;
my  $etat;
### $etat =0  access  denied  $etat <> 0 access granted
my $complement;
### $complement stores the string add after the  dn in header send to application
#################  control section #############
# 
#
#
#
       if  (exists($session{$ATTRLDAP}{$LDAPCONTROL})) { #the user have the good authorization 
                                               # in order to access at application 
	   $etat =1 ;# We open tge gate
           $complement =$session{$ATTRLDAP}{$LDAPCONTROL};
#### begin:  here for he compatibility  with older lemonldap
            $complement=~  s/#.*//;
###  end  :  here for he compatibility  with older lemonldap



                                     } 
### end of control                                      
     if ($etat) { 
		 $log->notice("$ID_HANDLER: controle: $dn $uri :ACCEPTED");

      }   else {
#	  save_session ($id,'BIDON')  ;
#print STDERR "$ID_HANDLER/$MHURI: $id saving in cache level 2\n" if $DEBUG;
	  $log->notice("$ID_HANDLER: controle: $dn $uri :DENIED");

      }

untie %session;
		    unless ($etat) {
### c est meme pas la peine essayer  !
			return FORBIDDEN;;
			exit;
                    }
#########  ici tout est ok pour moi 

#recuperation de l attribut multivalue en fonction  de l url 


############################################
############################################
##  new feature , in the new release all header is saving in session
##  info session MUST BE BEGAN with uid..
if ($complement =~ /^uid/)  {
$ligne_h = $complement;


}  else 
{

$ligne_h = $dn;
if (defined($complement)) {
$ligne_h.=":$complement";
} 
}



	    } ### end of search in cache 1 ,2 and 3

   } ##  end of cache level 1 
 if ($id eq $CLIENT){
## corresponding at :
#cache  level 1 test 
# unless($id eq $CLIENT)
      $ligne_h=$CACHE1_ENTETE; 
      $log->info("$ID_HANDLER/$MHURI: match in cache level 1 for $id");

  }


#  all is done for this phase  we can cache the header .
# now we must up date the cache level i1 and 2 (IPC)

##### I must to resume here (the three caches ) 
####
###
##
#
$CLIENT=$id;
$CACHE1_ENTETE=$ligne_h; 
$log->info ("$ID_HANDLER: $id saving in cache level 1");
      if (($IPCNB) && (defined (%STACK))) { #we want cache IPC level 2
	  save_session ($id,$ligne_h)  ;
$log->info( "$ID_HANDLER/$MHURI: $id saving in cache level 2");
          untie %STACK ;
      }
     ###  add user in access log
      my ($user) = $ligne_h=~ /(^u.+?),/;
$r->user($user) if $user ;

my $hcode =encode_base64($ligne_h,''); 
$log->info ("$ID_HANDLER/$MHURI: header before encoding: $ligne_h");
$log->info ("$ID_HANDLER/$MHURI: header after encoding: $hcode");

###############  We can insert the header #####################
my $entete_spec = "Basic ";
$entete_spec.=$hcode."\n";
$r->header_in('Authorization'=> $entete_spec);
###############################################################
# STOP_COOKIE is used to hide cookie value to the remote application
        # (to avoid programmers to usurp client identities)
        if($STOPCOOKIE) {
	    $r->headers_in->do(sub {
		(my $cle ,my $valeur) = @_;
		if ($valeur=~ /$COOKIE/) {
		    $_[1]=~ s/$COOKIE=(.+?)\b//;
		    $_[1]=~ s/;\s+;/;/;
		    $_[1]=~ s/^\s?;//;
		    $_[1]=~ s/^\s+;//;
         $log->debug  ("$ID_HANDLER/$MHURI: STOPCOOKIE done");
 		}
		1;
	    });
        }



############################ 
 return OK if $PROXY ;
 return DECLINED unless $PROXY;      
############################
#################
# end of handler#
#################
}
            
sub proxy_handler {
    my $r = shift;
        # Transformation: GET /index.html becomes http://servername/index.html
        # $url contains the real value (hided server)
        # $url_init contains the asked value
my $log=$r->log;   
 
   my $url =$r->uri;
    $url .="?".$r->args if ($r->args);
    my %entete = $r->headers_in();
    my $url_init= $BASEPUB.$url;
    my $uuu = $url;
### only for test################
#    $uuu=~ s/handler/ressource/;
#################################
    $url = $BASEPRIV.$uuu;
    $log->info("$ID_HANDLER/$MHURI: URLPRIV ACTIVED: $url  
                     URLPUB REQUESTED : $url_init");

     my $request = HTTP::Request->new($r->method, $url);
    $r->headers_in->do(sub {
	$request->header(@_);
	1;
    });
        # copy POST data, if any
    if($r->method eq 'POST') {
	my $len = $r->header_in('Content-length');
	my $buf;
	$r->read($buf, $len);
	$request->content($buf);
	$request->content_type($r->header_in('Content-Type'));
    }
###begin: some modification like mod_proxy does
if ($request->header('Host')){
    my $host =$request->header('Host') ;
    $host=~ s/$BASEPUB/$BASEPRIV/ ;
    $request->header('Host' => $host);

}
### here I modify keep alive by close
if ($request->header('Connection')){
      $request->header('Connection' => 'close');
}
my $messagelog ="$ID_HANDLER/$MHURI: request ".$request->as_string() ;
 $log->debug($messagelog);  
  
   if ($RECURSIF) { 
     $log->debug  ("$ID_HANDLER/$MHURI: RECURSIF LWP DESACTIVED");
    my @tt= ('HEAD');
    $UA->requests_redirectable(\@tt);
}

        # LWP proxy
# I 'll forward  on an  external proxy 
if ($PROXYEXT) {
    $log->debug("$ID_HANDLER/$MHURI:OUTPUT PROXY:$PROXYEXT");
    $UA->proxy(http  => $PROXYEXT);
} 
    my $response = $UA->request($request);
### begin: somes bad requests have bad header . 
    my $content = $response->header('Content-type');
     $content=~ s/,/;/g ;
### end: somes bad requests have bad header . 
    $r->content_type($content);
### begin: I correct on the fly some incomming header like mod_proxy does
 $messagelog= $response->as_string();
    $log->debug($messagelog);


if ($response->header('Location')) {

  my $h =$response->header('Location');
$h =~ s/:\d+//; 
my $basepriv =$BASEPRIV;
$basepriv=~ s/:\d+//;
$h=~ s/$basepriv/$BASEPUB/ ;
$response->header('Location' => $h);
}
### end: I correct on the fly some incomming header like mod_proxy does

    $r->status($response->code);
    $r->status_line(join " ", $response->code, $response->message);
    $response->scan(sub {
	$r->headers_out->add(@_);
    });

    if ($r->header_only) {
	$r->send_http_header();
	return OK;
    }

    $content = \$response->content;
    $r->content_type('text/html') unless $$content;
    $r->send_http_header;
    $r->print($$content || $response->error_as_HTML);
 
   $log->notice ("$ID_HANDLER/$MHURI: response sent");
    return OK;




}
sub goPortal {
	my  $r = shift;
        my $op= shift;
       my $log=$r->log;
        my $urlc_init = $BASEPUB.$r->uri;
        $urlc_init.="?".$r->args if $r->args; 
    my  $urlc_initenc = encode_base64($urlc_init,"");
       	$r->header_out(location =>$PORTAL."?op=$op&url=$urlc_initenc");
        my $messagelog =  "$ID_HANDLER : Redirect to portal (url was ".$urlc_init.")";
$log->info($messagelog); 

	return REDIRECT;
        exit;
}

sub   expire_session {
my $id = shift;
tied(%STACK)->shlock ;
my $tmpvar = $STACK{'QUEUE'};
#my $ligne= Dumper ($tmpvar);
#print STDERR "eZZZ : $ligne \n";
my @tmp ;
if ($tmpvar) { 
@tmp= split /#/,$tmpvar ;
}  
#$ligne= Dumper (@tmp);
#print STDERR "eXXX : $ligne \n";
my @stack;
@stack= grep ($id ne $_ ,@tmp);
unshift @stack, $id;
#### for avoid stack overflow 
my %hashs;
foreach (@stack) {
$hashs{$_}=1;

}



my $config = \@stack;
#my $configsx=Dumper ($config);
#print STDERR "final = $configsx\n";
  if ($#stack > $IPCNB ) {
  my $to_delete = pop @stack ;
  print STDERR "sup  $to_delete\n";
  delete $STACK{$to_delete}; 
   }
#### for avoid stack overflow 
foreach (keys %STACK)  {
next if /QUEUE/ ;
delete $STACK{$_} unless $hashs{$_} ;
 }
#$Data::Dumper::Purity=1;
#$Data::Dumper::Terse=1;
my $buffer;
foreach (@stack){
    $buffer.="$_"."#";
}
$buffer=~ s/#$//; 
$config = \@stack;
#$configsx=Dumper ($config);
#print STDERR "essss : $configsx \n";
#my $configs=Dumper ($buffer);
#print STDERR "errr : $configs \n";

$STACK{'QUEUE'} = $buffer;
tied(%STACK)->shunlock ;
}
sub   save_session {
my $id = shift;
my $trace = shift;
#tied(%STACK)->shlock ;
$STACK{$id} = $trace;
#tied(%STACK)->shunlock ;
}
sub get_match_sub   {
    my $tablemh= shift;
my $code = "sub {local \$_ = shift;\n"; 
foreach (@$tablemh) {
$code .= "return \"$_->{HANDLER}\"  if /^\\$_->{MOTIFIN}/i;\n";  
}
$code.= "1;}\n";
return $code;
}



sub parseConfig {
    my $tmp =shift;
    $PROXY= $tmp->{Enabledproxy};
    $KEYIPC=$tmp->{IpcKey};
    $IPCNB= $tmp->{IpcNb};
    $ATTRLDAP= $tmp->{AttrLdap};
    $LDAPCONTROL=$tmp->{CodeAppli};
    $DISABLEDCONTROL=$tmp->{Disabled};
    $BASEPUB=$tmp->{BasePub};
    $BASEPRIV=$tmp->{BasePriv};
    $STOPCOOKIE= $tmp->{StopCookie};
    $PROXYEXT = $tmp->{ProxyExt};
    $RECURSIF= $tmp->{Recursive};
    $PORTAL= $tmp->{Portal} if $tmp->{Portal} ;

## Multihoming I must collect line of multihoming
    $MULTIHOMINGLINE=$tmp->{MultiHoming} ;   

     }
sub parseConfigMH {
    my $tmp =shift;
    $PROXY= $tmp->{Enabledproxy} if $tmp->{Enabledproxy}  ;
    $KEYIPC=$tmp->{IpcKey} ;
    $IPCNB= $tmp->{IpcNb};
    $ATTRLDAP= $tmp->{AttrLdap};
    $LDAPCONTROL=$tmp->{CodeAppli};
    $DISABLEDCONTROL=$tmp->{Disabled};
    $BASEPRIV=$tmp->{BasePriv};
    $STOPCOOKIE= $tmp->{StopCookie};
    $PROXYEXT = $tmp->{ProxyExt};
    $RECURSIF= $tmp->{Recursive};
## Multihoming I must collect line of multihoming
    $MULTIHOMINGLINE=$tmp->{MultiHoming} ;   

     }


1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Lemonldap::Handlers::Generic - Perl extension for Lemonldap sso system

Lemonldap::Handlers::Generic4a2  - Handler for Apache2 Lemonldap SSO system 

=head1 SYNOPSIS

In httpd.conf 

<location mylocation>  
 Lemonldap::Handlers::Generic;
 
</location>

=head1 DESCRIPTION


=head2 Parameters

=head4 LemonldapConfig "/foo/bar/file_config.xml"

 The filename of the mean XML Config   :It's REQUIRED 
 
=head4 LemonldapConfigIpcKey GLUE

 The identifier of config segment IPC  :It's REQUIRED 

=head4 LemonldapDomain foo.bar

 If present , it fixes the value of domain for the  application protected by  this handler (see below) 

=head4  LemonldapHandlerId  <xml section>

 If present the configuration of handler is read from XML config backend.
You can overlay XML config backend with httpd.conf 


=head4  LemonldapEnabledproxy  0|1

 0 : don't use built-in proxy (configuration  must use with mod_proxy or mod_rewrite )
 1 : use built-in proxy
 default : 0 

=head4  LemonldapDEBUG  0|1

 0 : mode debug disabled
 1 : mode debug enabled
 default : 0 


=head4  LemonldapIpcNb     0..nn 

 IPNB is the number of session which you want to keep in cache evel 2 (IPC) 

 min value : 0  (don't use cache IPC level2) 
 max value : ???  : It depends of your server 
 recommended : 100
 The youngest value replace the oldest .

=head4  LemonldapIpcKey   '4 carac'

 A string of 4 caracteres (see IPC::Shareable doc) 
 It must be 'unique'  . 

=head4  LemonldapAttrLdap  'string'

 The first level of hash session  , whi can to be the name of LDAP attribute
 see below

=head4 LemonldapCodeAppli 'string'

 The second  level of hash session  , whi can to be the code of application
 The access of %session if $session{LemonldapAttrLDAP}{lemonldapCodeAppli} 
 with the value of key = profil .
 
=head4 LemonldapDisabled  0|1

 0 : Control the request (default)
 1 : Don't control the request (useful for jpeg ) 

=head4 LemonldapStopCookie  0|1

 0 : Let pass the lemonldap cookie to application (default).
 1 : Block the lemonldap cookie. 

=head4 LemonldapRECURSIVE  0|1

 0 : Let LWP chases redirection (default).
 1 : Let Client chases redirection instead LWP. 

=head4 LemonldapProxyExt  0|1

 0 : Let LWP resquets on ressource (default).
 1 : force LWP to request via an external proxy. 

=head4 LemonldapSession  'cachelevel 3'

 It is the name of XML section  which  describes the backend used in order to store  the  session .

=head4 LemonldapCookie 'name_of_cookie'

 eg: lemontest
 
=head4 LemonldapBasePub

 The public host name  avaiable by user 

=head4 LemonldapBasePriv

 The private host name  not avaiable by user 

=head4 LemonldapPortal

 The url of login page 

=head1 SEE ALSO

Lemonldap(3), Lemonldap::Portal::Standard

http://lemonldap.sourceforge.net/

"Writing Apache Modules with Perl and C" by Lincoln Stein E<amp> Doug
MacEachern - O'REILLY

=over 1

=item Eric German, E<lt>germanlinux@yahoo.frE<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Eric German E<amp> Xavier Guimard

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






