package Lemonldap::Handlers::Generic;
use strict;
use warnings;
#####  use ######
use Apache();
use Apache::URI();
use Apache::Constants qw(:common :response);
use MIME::Base64;
use LWP::UserAgent;
use Lemonldap::Config::Parameters;
use Lemonldap::Config::Initparam;
use Lemonldap::Handlers::Utilities;
use Apache::Log();
#### common declaration #######
our ( @ISA, $VERSION, @EXPORTS );
$VERSION = '1.02';
our $VERSION_LEMONLDAP = "1.2";
our $VERSION_INTERNAL  = "0.03-4";

####
####
#### my declaration #########
my  $UA;
my $CLIENT;
my $__STACK;
my $CACHE1_ENTETE;
my $ID_HANDLER_IN_PROCESS;
my $ANONYMOUSFUNC;
my $NOM = __PACKAGE__;
my %CONFIG;
my $__cookie;
my  $MHURI;
my $SAVE_MHURI;
my $SELECTOR;
#############################
@ISA = qw(LWP::UserAgent );

sub handler {
    my $r = shift;
########################
##  log initialization
########################
    my $log = $r->log;
    my $messagelog;
    $__STACK = 0;
########################
## collect httpd param
########################
    my $con = $r->dir_config();
    my $conf = &Lemonldap::Config::Initparam::init_param_httpd($con);
        %CONFIG = %$conf;
### I will try  retieve ID_HANDLER from  httpd conf
    if ( $CONFIG{ID_HANDLER} ) {
        $messagelog =
"$NOM Phase : handler initialization LOAD ID_HANDLER httpd.conf:$CONFIG{ID_HANDLER} : succeded";
    }
    else {

# I don't find anything for this handler in order to make link with XLM conf section
        $messagelog =
"$NOM: Phase : handler initialization LOAD ID_HANDLER httpd.conf:failed";
    }
    $log->debug($messagelog);

############################################
    my $ref = $CONFIG{ID_HANDLER};
    $ref =~  s/\/.+// ;

    unless ( $ref eq $ID_HANDLER_IN_PROCESS ) {
## It doesn t be in the same context ;
        $CONFIG{OK} = 0;
        undef $CLIENT;
        undef $SAVE_MHURI;
    }
## now I save the context of handler
    $ID_HANDLER_IN_PROCESS = $CONFIG{ID_HANDLER};
    if ( $CONFIG{OK} ) {
        $log->debug(
"$CONFIG{ID_HANDLER}: Phase : handler initialization one step beyond"
        );
    }
    unless ( $CONFIG{OK} ) {

        my $conf = &Lemonldap::Config::Initparam::init_param_httpd($con);
        %CONFIG = %$conf;
        $log->debug(
"$CONFIG{ID_HANDLER}: Phase : handler initialization LOAD XML file $CONFIG{FILE} and $CONFIG{GLUE} from  httpd.conf"
        );
        $log->debug("$CONFIG{ID_HANDLER}: domain matched $CONFIG{DOMAIN}");
        $conf = &Lemonldap::Config::Initparam::init_param_xml( \%CONFIG );
        $log->debug("$conf->{message}");
### merge xml and httpd param , httpd > xml
        my $c = &Lemonldap::Config::Initparam::merge( \%CONFIG, $conf );
        %CONFIG = %$c;
        $CONFIG{KEYIPC} .= "-$$" if ( $CONFIG{KEYIPC} );
        $CONFIG{OK} = 1;
        $log->info("$CONFIG{ID_HANDLER} end of initialization");

## addon  for ICS
        if ( ( $CONFIG{ICS} ) && !($ANONYMOUSFUNC) ) {
            my $sub =
              &Lemonldap::Config::Initparam::built_functionics( $CONFIG{ICS} );
            $ANONYMOUSFUNC = eval $sub;
            $log->debug(
                "$CONFIG{ID_HANDLER}: Phase : ICS TABLE  LOADED : $sub");
        }
## addon for multihoming 
        if (($CONFIG{MULTIHOMING}) && !($SELECTOR)) {
 my $sub = $CONFIG{SUB} ; 
 $SELECTOR = eval $sub;
}
 

        foreach ( keys %CONFIG ) {
            $log->info("$CONFIG{ID_HANDLER} $_  => $CONFIG{$_}");
        }
    


}

##### end of initialization
    my $uri = $r->uri;

    $log->info("$CONFIG{ID_HANDLER} :uri  requested: $uri");
####  multihoming 
    if ($CONFIG{MH})  {
  	$MHURI = $SELECTOR->($uri);
# Stop  process  if no multihosting
if (($MHURI eq '1') || (!($MHURI))) { 
    $log->warn ("$CONFIG{ID_HANDLER} :multihoming failed for  $uri") ;
    return DECLINED  ;
}
## now I switche config with mh config ;
#if ($MHURI  ne $SAVE_MHURI) {
# reload conf   
$log->info("$CONFIG{ID_HANDLER} :SWITCH CONFIG $MHURI");

 my $c = &Lemonldap::Config::Initparam::mergeMH( \%CONFIG, $MHURI );
        %CONFIG = %$c;
#my $f= Dumper (%CONFIG);
#print STDERR  "GERMAN $f\n"; 
undef $CLIENT;

#}   
$log->info("$CONFIG{ID_HANDLER} :MULTIHOMING ON");

$SAVE_MHURI= $MHURI; 
       foreach ( keys %CONFIG ) {
            $log->info("$CONFIG{ID_HANDLER} $_  => $CONFIG{$_}");
        }
    

}



    if ( ( $CONFIG{ICS} ) && ( $ANONYMOUSFUNC->($uri) eq 'OK' ) ) {
        $log->info("$CONFIG{ID_HANDLER} :uri ICS matched: $uri");
        return DECLINED;
    }

    if ( $CONFIG{PROXY} ) {
        $UA = __PACKAGE__->new;
        $UA->agent( join "/", __PACKAGE__, $VERSION );

        $log->info("$CONFIG{ID_HANDLER}:  Build-in proxy actived");
        $r->handler("perl-script");
        $r->push_handlers( PerlHandler => \&proxy_handler );
    }

    # Stop  process  if protection is disabled
    return DECLINED if ( $CONFIG{DISABLEDCONTROL} );

    # is this area protected
    # configuration check
    #
    #

    # AUTHENTICATION
    # cookie search
    my %entete = $r->headers_in();
    my $idx    = $entete{'Cookie'};
    $__cookie = $idx;

    # Load id value from cookie
    $idx =~ /$CONFIG{COOKIE}=([^; ]+)(;?)/;
    my $id = $1;
    unless ($id) {

        # No cookie found: redirect to portal
        $messagelog = "$CONFIG{ID_HANDLER} : No cookie found for " . $r->uri;
        $log->info($messagelog);
        return &Lemonldap::Handlers::Utilities::goPortal( $r, \%CONFIG, 'c' );
    }
    $log->info("$CONFIG{ID_HANDLER}: id session : $id");

    # SESSIONS CACHE

    #cache  level 1 test
    my $ligne_h;
    if ( $id eq $CLIENT ) {
        $ligne_h = $CACHE1_ENTETE;
        $log->info("$CONFIG{ID_HANDLER}: match in cache level 1 for $id");

    }
    else {

        # Level 2 test by IPC
        $log->info("$CONFIG{ID_HANDLER}: No match in cache level 1 for $id");
        if ( $CONFIG{IPCNB} ) {    ####  We want use level 2 cache
	    my $message;      
       ( $ligne_h, $message ) =
              &Lemonldap::Handlers::Utilities::cache2( \%CONFIG, $id );
            $__STACK = 1;
            $log->info("$message");
        }    ####  We want use level 2 cache

        unless ($ligne_h) {    # no match in cache level 1 and 2
            $log->info(
                "$CONFIG{ID_HANDLER} :  Search  in cache level 3 for $id");
######
######
######   search in backend cache
######
            my $dn;
            my $etat = 0;    # 0 = denied ,NULL = not found other values is OK ;
            ( $etat, $dn ) =
              &Lemonldap::Handlers::Utilities::cache3( \%CONFIG, $id );
              $ligne_h =$etat if $etat ;
#################  control section #############
            #
            #
            #
            #
            if ( ($__STACK ==1) && ($etat) && ($etat ne 'NULL'))  {
                $__STACK = 0;
                $log->info("$CONFIG{ID_HANDLER}: $id saving in cache level 2");	
		&Lemonldap::Handlers::Utilities::save_session($id,$ligne_h) ;
             }
            
            return &Lemonldap::Handlers::Utilities::goPortal( $r, \%CONFIG, 't', $id ) if $etat eq 'NULL';
            $log->debug("$CONFIG{ID_HANDLER}: SESSION FIND IN CACHE 3 FOR:$id");
            unless ($etat) {
                $log->notice("$CONFIG{ID_HANDLER}: controle: $dn $uri :DENIED");
                return FORBIDDEN;
            }
            $log->notice("$CONFIG{ID_HANDLER}: controle: $dn $uri :ACCEPTED");

#########  ici tout est ok pour moi

            #recuperation de l attribut multivalue en fonction  de l url

        }    ### end of search in cache 2 & 3

    $CLIENT        = $id;
    $CACHE1_ENTETE = $ligne_h;
    $log->debug("$CONFIG{ID_HANDLER}: $id saving in cache level 1");   
    }

    #  all is done for this phase  we can cache the header .
    # now we must up date the cache level i1 and 2 (IPC)

##### I must to resume here (the three caches )
####
###
##
    #
   
   
   # }
    ###  add user in access log
    my ($user) = $ligne_h =~ /(^u.+?),/;
    $r->user($user) if $user;

    my $hcode = encode_base64( $ligne_h, '' );
    $log->info("$CONFIG{ID_HANDLER}: header before encoding: $ligne_h");
    $log->info("$CONFIG{ID_HANDLER}: header after encoding: $hcode");
###############  We can insert the header #####################
    my $entete_spec = "Basic ";
    $entete_spec .= $hcode . "\n";
    $r->header_in( 'Authorization' => $entete_spec );
###############################################################
    # STOP_COOKIE is used to hide cookie value to the remote application
    # (to avoid programmers to usurp client identities)
    if ( $CONFIG{STOPCOOKIE} ) {
        my $cook =
          &Lemonldap::Handlers::Utilities::cookie( $__cookie, $CONFIG{COOKIE} );
        $r->header_in( 'Cookie' => $cook );

    }

############################
    return OK if $CONFIG{PROXY};
    return DECLINED unless $CONFIG{PROXY};
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
    #add this in order to log
    my $log = $r->log;
    my $url = $r->uri;

    $url .= "?" . $r->args if ( $r->args );
    my %entete   = $r->headers_in();
    my $url_init = $CONFIG{BASEPUB} . $url;
    my $uuu      = $url;
    $url = $CONFIG{BASEPRIV} . $uuu;
    $log->info(
        "$CONFIG{ID_HANDLER}: URLPRIV ACTIVED: $url  
                     URLPUB REQUESTED : $url_init"
    );

    my $request = HTTP::Request->new( $r->method, $url );
    $r->headers_in->do(
        sub {
            $request->header(@_);
            1;
        }
    );

    # copy POST data, if any
    if ( $r->method eq 'POST' ) {
        my $len = $r->header_in('Content-length');
        my $buf;
        $r->read( $buf, $len );
        $request->content($buf);
        $request->content_type( $r->header_in('Content-Type') );
    }
###begin: some modification like mod_proxy does
    if ( $request->header('Host') ) {


        my $host = $request->header('Host');
        (my $priv) = $CONFIG{BASEPRIV}=~ /:\/\/(.+)/ ; 
        (my $pub) = $CONFIG{BASEPUB}=~ /:\/\/(.+)/ ; 
      	$host =~ s/$pub/$priv/;
        $request->header( 'Host' => $host );

    }
### here I modify keep alive by close
    #if ($request->header('Connection')){
    #      $request->header('Connection' => 'close');
    #}

    my $messagelog = "$CONFIG{ID_HANDLER}: request " . $request->as_string();
    $log->debug($messagelog);
    if ( $CONFIG{RECURSIF} ) {
        $log->debug("$CONFIG{ID_HANDLER}: RECURSIF LWP DESACTIVED");
        my @tt = ('HEAD');
        $UA->requests_redirectable( \@tt );
    }

    # LWP proxy
    # I 'll forward  on an  external proxy
    if ( $CONFIG{PROXYEXT} ) {
        $log->debug("$CONFIG{ID_HANDLER}:OUTPUT PROXY:$CONFIG{PROXYEXT}");

        $UA->proxy( http => $CONFIG{PROXYEXT} );
    }
    my $response = $UA->request($request);
### begin: somes bad requests have bad header .
    $messagelog = $response->as_string();
    $log->debug($messagelog);
    my $content = $response->header('Content-type');
    $content =~ s/,/;/g;
### end: somes bad requests have bad header .
    $r->content_type($content);
### begin: I correct on the fly some incomming header like mod_proxy does
    if ( $response->header('Location') ) {
        my $h = $response->header('Location');
        $h =~ s/$CONFIG{BASEPRIV}/$CONFIG{BASEPUB}/;
        $response->header( 'Location' => $h );
    }
### end: I correct on the fly some incomming header like mod_proxy does

    $r->status( $response->code );
    $r->status_line( join " ", $response->code, $response->message );
    $response->scan(
        sub {
            $r->headers_out->add(@_);
        }
    );

    if ( $r->header_only ) {
        $r->send_http_header();
        return OK;
    }

    $content = \$response->content;

    $r->content_type('text/html') unless $$content;
    $r->send_http_header;
    $r->print( $$content || $response->error_as_HTML );
    $log->notice("$CONFIG{ID_HANDLER}: $url response sent");
    return OK;

}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

    Lemonldap::Handlers::Generic - Perl extension for Lemonldap sso system

    Lemonldap::Handlers::Generic4a2 - Handler for Apache2 Lemonldap SSO
    system
    
    Lemonldap::Handlers::GenericSSL - Handler full SSL for Lemonldap sso system

    Lemonldap::Handlers::Generic4a2 - Handler full SSL  Apache2 Lemonldap SSO

    Lemonldap::Handlers::GenericMH1 - Handler with multihoming facilities




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






