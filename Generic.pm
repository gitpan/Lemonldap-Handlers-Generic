package Lemonldap::Handlers::Generic;
use strict;
use warnings;
#####  use ######
use Apache();
use Apache::URI();
use Apache::Constants qw(:common :response);
use Apache::Session::Memorycached;
use Apache::ModuleConfig;
use MIME::Base64;
use LWP::UserAgent;
use Lemonldap::Config::Parameters;
#print STDERR "je passe phase 0\n";

#if(DEBUG) {
	use Data::Dumper;
#}
#### common declaration #######
our (@ISA, $VERSION, @EXPORTS);
$VERSION = '0.01';
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
our $NOM=  __PACKAGE__ ;
#############################
@ISA = qw(LWP::UserAgent Apache::ModuleConfig);
if($ENV{MOD_PERL}) {
	push @ISA, 'Dynaloader';
	__PACKAGE__->bootstrap($VERSION);
			}
#Apache->push_handlers( PerlChildInitHandler=>\&childInit );

###############################
##
##
#our ($VERSION, @EXPORTS);



sub handler {
	my $r=shift;
#### retrieve directive and build variables
#### but I 'll try it one time 
if ($LDAPCONTROL) {  
print STDERR "$NOM: Phase : handler initialization one step beyond\n" if $DEBUG ; 
}
unless ($LDAPCONTROL) {

$DEBUG = $r->dir_config('LemonldapLogDEBUG')  ;
print STDERR "$NOM: Phase : handler initialization DEBUG => $DEBUG\n" if $DEBUG ; 
print STDERR "$NOM: Phase : handler initialization LOAD XML file from  httpd.conf\n" if $DEBUG ; 
### I will try  retieve XML  from  httpd conf 
$FILE = $r->dir_config('LemonldapXML');
print STDERR "$NOM: Phase : handler initialization LOAD XML file $FILE from  httpd.conf\n" if $DEBUG ; 

### retrieve domain xml 
print STDERR "$NOM: Phase : handler initialization LOAD DOMAIN  httpd.conf\n" if $DEBUG ; 
### I will try  retieve domain  from  httpd conf 
$DOMAIN = $r->dir_config('LemonldapDomain');
####
print STDERR "$NOM: Phase : handler initialization LOAD ID_HANDLER httpd.conf\n" if $DEBUG ; 
### I will try  retieve ID_HANDLER from  httpd conf 
$ID_HANDLER = $r->dir_config('LemonldapHandlerId');
      if  ($ID_HANDLER) {
print STDERR "$NOM: Phase : handler initialization LOAD ID_HANDLER httpd.conf:$ID_HANDLER : succeded\n" if $DEBUG ; 

  } else { 
 # I don't find anything for this handler in order to make link with XLM conf section
print STDERR "$NOM: Phase : handler initialization LOAD ID_HANDLER httpd.conf:failed\n" if $DEBUG ; 
 } 
##### now I'll load conf from XML file 
####  sereval  cases 
#### I have domain but nothing for id_handler in httpd.conf
#### I have not domain and  id_handler so 
#### I have both
####  Normaly the cookie is  got from domain 
####  I 'll try to load domain ONLY if httpd.conf don't have domain 
print STDERR "$NOM: Phase : handler initialization try to load XML conf\n" if $DEBUG ; 
$CONF= Lemonldap::Config::Parameters->new (
                                                file => $FILE ,
					      cache => 'CONF' );
	if ($CONF) {
print STDERR "$NOM: Phase : handler initialization LOAD XML conf :succeded \n" if $DEBUG ; 
} else {
print STDERR "$NOM: Phase : handler initialization LOAD XML conf : failed \n" if $DEBUG ; 
 
}


### here conf from XML is ready 
print STDERR "$NOM: Phase : handler initialization LOAD XML conf\n" if $DEBUG ; 
### I'll search XML section from ID_HANDLER

if ($ID_HANDLER) {
    my $tmpconf;
    if ($DOMAIN) {  
    	$GENERAL = $CONF->getDomain($DOMAIN) ;
	my $tmpconf = $GENERAL->{$ID_HANDLER}; 
	$COOKIE = $GENERAL->{cookie};
        $PORTAL=$GENERAL->{login};
        $CACHE =$GENERAL->{cache} ;
        parseConfig($tmpconf);
    		}  else 		{ 
	$tmpconf= $CONF->{$ID_HANDLER} ;
        parseconfig($tmpconf); 
			}
	} 

#now I read httpd.conf in order to  overlay the XML config 
#
#
#
#
}
### I 'll do this only once
unless ($LDAPCONTROL) {
####################################################
my $_proxy = $r->dir_config('LemonldapEnabledproxy');
$PROXY= $_proxy if $_proxy;
####################################################
my $_keyIPC= $r->dir_config('LemonldapIPCKey');
$KEYIPC= $_keyIPC if $_keyIPC;
####################################################
my $_IPCNB= $r->dir_config('LemonldapIPCNB');
$IPCNB= $_IPCNB if $_IPCNB;
####################################################
my $_attrldap= $r->dir_config('LemonldapAttrLDAP');
$ATTRLDAP= $_attrldap if $_attrldap;
####################################################
my $_ldapcontrol= $r->dir_config('LemonldapCodeAppli');
$LDAPCONTROL=$_ldapcontrol  if $_ldapcontrol;
####################################################
my $_disabledcontrol= $r->dir_config('LemonldapDisabled');
$DISABLEDCONTROL=$_disabledcontrol  if $_disabledcontrol;
####################################################
my $_cache= $r->dir_config('LemonldapCache');
$CACHE=$_cache  if $_cache;
####################################################
my $_stop= $r->dir_config('LemonldapStopCookie');
$STOPCOOKIE=$_stop  if $_stop;
####################################################
my $_mode= $r->dir_config('LemonldapRecursif');
$RECURSIF=$_mode  if $_mode;
####################################################
my $_proxyext= $r->dir_config('LemonldapProxyExt');
$PROXYEXT=$_mode  if $_proxyext;
####################################################

#
#
#
# Result 
print STDERR "$NOM: Phase : handler initialization VARIABLES
PROXY           => $PROXY
KEYIPC          => $KEYIPC
IPCNB           => $IPCNB
ATTRLDAP        => $ATTRLDAP
LDAPCONTROL     => $LDAPCONTROL
DISABLEDCONTROL => $DISABLEDCONTROL
RECURSIF        => $RECURSIF
STOPCOOKIE      => $STOPCOOKIE\n" if $DEBUG ; 

}
##### end of initialization 
## deleted those line  
my $uri =$r->uri;
print STDERR "$NOM :uri  requested: $uri\n";
##### end deleted lines 
	if($PROXY){
$UA = __PACKAGE__->new;
$UA->agent(join "/", __PACKAGE__, $VERSION);
	
       print STDERR "$NOM:  Build-in proxy actived\n" ;
        $r->handler("perl-script");
        $r->push_handlers( PerlHandler => \&proxy_handler );
	}
# Stop  process  if protection is disabled
	return DECLINED if  ($DISABLEDCONTROL);
#	return DECLINED unless ($PROXY);
# is this area protected
# configuration check
unless ($COOKIE) {
####################################################
my $_cookie = $r->dir_config('LemonldapCookie');
$COOKIE= $_cookie if $_cookie;
####################################################
my $_basepub= $r->dir_config('LemonldapBasePub');
$BASEPUB=$_basepub  if $_basepub;
####################################################
my $_basepriv= $r->dir_config('LemonldapBasePriv');
$BASEPRIV=$_basepriv  if $_basepriv;
####################################################
my $_portal= $r->dir_config('LemonldapPortal');
$PORTAL=$_portal  if $_portal;
####################################################
print STDERR "$NOM: Phase : handler AUTHORIZATION VARIABLES
COOKIE   => $COOKIE
BASEPUB  => $BASEPUB
BASEPRIV => $BASEPRIV
PORTAL   => $PORTAL\n" if $DEBUG ; 

}
#### Read cache info from  XML config 
# 
#
	unless ($SERVERS) {
my $xmlsession= $CONF->findParagraph('session',$CACHE);
#my $ligne= Dumper ($xmlsession) ;
#print STDERR "ligne : $ligne\n";
my $refserversession =$xmlsession->{memcached}->{servers} ;
$SERVERS = eval $refserversession;
print STDERR "$NOM: Phase : handler AUTHORIZATION CACHE CONFIG:servers=>$refserversession \n" if $DEBUG ; 
}
#
#

	# AUTHENTICATION
	# cookie search
	my %entete =$r->headers_in();
	my $idx =$entete{'Cookie'} ;
	# Load id value from cookie
	$idx =~ /$COOKIE=([^; ]+)(;?)/o;
	my $id =$1;
  #     $id='675314908c539c2c775072227c7b5d69';
  #      $id='c167b67d628deb1dcfe09de7aa7f927e';
	unless ($id) {
		# No cookie found: redirect to portal
		print STDERR "$NOM : No cookie found for ".$r->uri."\n" if $DEBUG;
		return goPortal($r,'c');
	}
	print STDERR "$NOM: id session : $id<--->$idx\n" if $DEBUG;
	# SESSIONS CACHE 

#cache  level 1 test 
	my $ligne_h;
 unless ($id eq $CLIENT) {
            # Level 2 test by IPC 
      print STDERR "$NOM: No match in cache level 1 for $id\n" if $DEBUG;
              if ($IPCNB)  {  ####  We want use IPC                 
                       print STDERR "$NOM :  search in cache level 2 for $id\n" if $DEBUG;
                tie %STACK ,'IPC::Shareable' , $KEYIPC, 
                            {create => 1 , mode => 0666};   
                 $ligne_h = $STACK{$id} ;      
                    if  ($ligne_h) {  ## match in ipc 
                       print STDERR "$NOM :  match in cache level 2 for $id\n" if $DEBUG;
                            expire_session($id) ;# put on the top of stack    
                                   } else  { 
      print STDERR "$NOM: No match in cache level 2 for $id\n" if $DEBUG;
}


## end no match in ipc
	                   }  ####  We want use IPC 

            unless ($ligne_h) { # no match in cache level 1 and 2 
		print STDERR "$NOM :  Search  in cache level 3 for $id\n" if $DEBUG;
###### 
######
######   search in backend cache 
######
		my %session ;
   tie %session, 'Apache::Session::Memorycached', $id,
      {
         servers        => $SERVERS,
      };
 unless ($session{dn}) {  ##  the cookie is present but i can't  retrieve session
                         ##  tree causes : Too many connection are served.              
                         ##                the server of session was restarted                
                         ##                It's time out                 
           print STDERR "$NOM: ERROR OF LOCKING  ON :$id\n"  if $DEBUG; 
# I say it's time out 
	return goPortal($r,'t');
                       }
#here  we are retrieve session        
           print STDERR "$NOM: SESSION FIND FOR:$id\n"  if $DEBUG; 
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
       if  ($session{$ATTRLDAP}{$LDAPCONTROL}) { #the user have the good authorization 
                                               # in order to access at application 
	   $etat =1 ;# We open tge gate
           $complement =$session{$ATTRLDAP}{$LDAPCONTROL};
                                   } 
### end of control                                      
     if ($etat) { 
	 print STDERR "$NOM: controle: $dn $uri :ACCEPTED \n" if $DEBUG;
      }   else {
#	  save_session ($id,'BIDON')  ;
#print STDERR "$NOM: $id saving in cache level 2\n" if $DEBUG;
         print STDERR "$NOM: controle: $dn $uri :DENIED \n" if $DEBUG;
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
$ligne_h = $dn;
if ($complement) {
$ligne_h.="$complement";
} 
	    } ### end of search in cache 1 ,2 and 3

   } ##  end of cache level 1 
 if ($id eq $CLIENT){
## corresponding at :
#cache  level 1 test 
# unless($id eq $CLIENT)
      $ligne_h=$CACHE1_ENTETE; 
      print STDERR "$NOM: match in cache level 1 for $id\n" if $DEBUG;

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
print STDERR "$NOM: $id saving in cache level 1\n" if $DEBUG;
      if (($IPCNB) && (%STACK)) { #we want cache IPC level 2
	  save_session ($id,$ligne_h)  ;
print STDERR "$NOM: $id saving in cache level 2\n" if $DEBUG;
          untie %STACK ;
      }
my $hcode =encode_base64($ligne_h,''); 
print STDERR "$NOM: header before encoding: $ligne_h\n" if ($DEBUG);
print STDERR "$NOM: header after encoding: $hcode\n" if $DEBUG;
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
		if ($valeur=~ /$COOKIE/o) {
		    my $tmp =~ /$COOKIE=.+b/o;
		    $_[1]=~ s/$tmp//;
		    print STDERR "$NOM: STOPCOOKIE done\n" if ($DEBUG);
		}
		1;
	    });
        }



############################ 

	return OK ;
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
    my $url =$r->uri;
    $url .="?".$r->args if ($r->args);
    my %entete = $r->headers_in();
    my $url_init= $BASEPUB.$url;
    my $uuu = $url;
    $uuu=~ s/handler/ressource/; 
   $url = $BASEPRIV.$uuu;
 print STDERR "$NOM: URLPRIV ACTIVED: $url  
                     URLPUB REQUESTED : $url_init\n" if ($DEBUG);       
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
	$request->content_type($r->content_type);
    }

    print STDERR  "$NOM: request ".$request->as_string()."\n" if($DEBUG);
   if ($RECURSIF) { 
       print STDERR  "$NOM: RECURSIF LWP DESACTIVED\n" if ($DEBUG);
    my @tt= ('HEAD');
    $UA->requests_redirectable(\@tt);
}

        # LWP proxy
# I 'll forward  on an  external proxy 
if ($PROXYEXT) {
    $UA->proxy(http  => $PROXYEXT);
} 
    my $response = $UA->request($request);
    $r->content_type($response->header('Content-type'));

    $r->status($response->code);
    $r->status_line(join " ", $response->code, $response->message);
    $response->scan(sub {
	$r->headers_out->add(@_);
    });

    if ($r->header_only) {
	$r->send_http_header();
	return OK;
    }

    my $content = \$response->content;
    $r->content_type('text/html') unless $$content;
    $r->send_http_header;
    $r->print($$content || $response->error_as_HTML);
    print STDERR "$NOM: response sent\n"  if ($DEBUG);
    return OK;




}
sub goPortal {
	my  $r = shift;
        my $op= shift;
        my $urlc_init = $BASEPUB.$r->uri;
        $urlc_init.="?".$r->args if $r->args; 
    my  $urlc_initenc = encode_base64($urlc_init,"");
       	$r->header_out(location =>$PORTAL."?op=$op&url=$urlc_initenc");
	print STDERR "$NOM : Redirect to portal (url was ".$urlc_init.")\n" if($DEBUG);
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
my $config = \@stack;
#my $configsx=Dumper ($config);
#print STDERR "final = $configsx\n";
  if ($#stack > $IPCNB ) {
  my $to_delete = pop @stack ;
  print STDERR "sup  $to_delete\n";
  delete $STACK{$to_delete}; 
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
tied(%STACK)->shlock ;
$STACK{$id} = $trace;
tied(%STACK)->shunlock ;
}
sub parseConfig {
    my $tmp =shift;
    $PROXY= $tmp->{Enabledproxy};
    $KEYIPC=$tmp->{IPCKey};
    $IPCNB= $tmp->{IPCNB};
    $ATTRLDAP= $tmp->{AttrLDAP};
    $LDAPCONTROL=$tmp->{CodeAppli};
    $DISABLEDCONTROL=$tmp->{Disabled};
    $BASEPUB=$tmp->{Basepub};
    $BASEPRIV=$tmp->{BasePriv};
    $STOPCOOKIE= $tmp->{StopCookie};
    $PROXYEXT = $tmp->{ProxyExt};
    $RECURSIF= $tmp->{Recusif};
        }
1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Lemonldap::Handlers::Generic - Perl extension for Lemonldap sso system

=head1 SYNOPSIS

In httpd.conf 

<location mylocation>  
 Lemonldap::Handlers::Generic;
 
</locaction>

=head1 DESCRIPTION


=head2 Parameters

=head3 LemonldapXML "/foo/bar/file_config.xml"

The filename of the mean XML Config   :It's REQUIRED 
 
=head3 LemonldapDomain foo.bar

If present , it fixes the value of domain for the  application protected by  this handler (see below) 

=head3  LemonldapHandlerId  <xml section>

If present the configuration of handler is read from XML config backend.
You can overlay XML config backend with httpd.conf 


=head3  LemonldapEnabledproxy  0|1

0 : don't use built-in proxy (configuration  must use with mod_proxy or mod_rewrite )
1 : use built-in proxy
default : 0 

=head3  LemonldapLogDEBUG  0|1

0 : mode debug disabled
1 : mode debug enabled
default : 0 


=head3  LemonldapIPCNB     0..nn 

IPNB is the number of session which you want to keep in cache evel 2 (IPC) 

min value : 0  (don't use cache IPC level2) 
max value : ???  : It depends of your server 
recommended : 100
The youngest value replace the oldest .

=head3  LemonldapIPCKey   '4 carac'

A string of 4 caracteres (see IPC::Shareable doc) 
 It must be 'unique'  . 

=head3  LemonldapAttrLDAP  'string'

The first level of hash session  , whi can to be the name of LDAP attribute
see below

=head3 LemonldapCodeAppli 'string'

The second  level of hash session  , whi can to be the code of application
The access of %session if $session{LemonldapAttrLDAP}{lemonldapCodeAppli} 
 with the value of key = profil .
 
=head3 LemonldapDisabled  0|1

0 : Control the request (default)
1 : Don't control the request (useful for jpeg ) 

=head3 LemonldapSTOPCOOKIE  0|1

0 : Let pass the lemonldap cookie to application (default).
1 : Block the lemonldap cookie. 

=head3 LemonldapRECURSIF  0|1

0 : Let LWP chases redirection (default).
1 : Let Client chases redirection instead LWP. 

=head3 LemonldapProxyExt  0|1

0 : Let LWP resquets on ressource (default).
1 : force LWP to request via an external proxy. 

=head3 LemonldapCache  'cachelevel 3'

It is the name of XML section  which  describes the backend used in order to store  the  session .

=head3 LemonldapCookie 'name_of_cookie'

 eg: lemontest
 
=head3 LemonldapBasePub

The public host name  avaiable by user 

=head3 LemonldapBasePriv

The private host name  not avaiable by user 

=head3 LemonldapPortal

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






