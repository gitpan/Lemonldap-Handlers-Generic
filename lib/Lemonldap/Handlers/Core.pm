package Lemonldap::Handlers::Core;
use strict;
our ( @ISA, $VERSION, @EXPORTS );
$VERSION = '2.00';
our $VERSION_LEMONLDAP = "2.0";
our $VERSION_INTERNAL  = "2.0";

sub locationRules  {
    my %param = @_;
# first retrieve session 
my $id = $param{'id'} ;
my $config =$param{'config'} ;
my $uri = $param{'uri'};
my $host = $param{'host'};
my $target =$param{'target'};
my $_session = Lemonldap::Handlers::Session->get ('id' => $id ,
                                                          'config' => $config) ;  
my $_trust  = Lemonldap::Handlers::Policy->get (  
	                                               'session' =>$_session ,
						       'parameters' => \%param );
my $result =$_trust->{profil} ; 
my $response = $_trust->{response} ;
my $h = {dn => $_session->{dn} ,uid=>$_session->{uid}, string => $_trust->{profil} , response => $_trust->{response} }; 
return $h;
}

sub getHeader {
    my %param = @_;
# first retrieve session 
my $result = $param{'profil'} ;
my $config =$param{'config'} ;
my $uid = $param{'uid'};
my $dn = $param{'dn'};
return Lemonldap::Handlers::Header->get('profil' => $result ,
                                               'dn' => $dn ,
                                               'config' => $config,
                                               'uid' => $uid);  
}

sub forgeHeader {
    my %param = @_;
# first retrieve session 
my $result = $param{'line'} ;
my $config =$param{'config'} ;
my $reponse= Lemonldap::Handlers::Header->forge('line' => $result ,
						'config' => $config,);
    my $h ={header => $reponse->{header},content => $reponse->{content} ,decoded =>$reponse->{clair} };
    return $h;
}
sub ParseHtml {
    my %param = @_;
# first retrieve session 
my $html = $param{'html'} ;
my $env = $param{'html'} ;
my $config =$param{'config'} ;
my $host= $param{'host'};
my $target= $param{'target'};
return Lemonldap::Handlers::Html->get('html' => $html ,
				       'host' => $host,
                                       'target' => $target,
                                       'config' => $config,
                                        'https' =>$env,);
}

package Lemonldap::Handlers::Html ;
sub get {
    my $class= shift;
     my %_param = @_;
    $_param{config}->{'PLUGINHTML'}= 'Lemonldap::Handlers::RewriteHTML'    unless $_param{config}->{'PLUGINHTML'} ; 
     my $api = $_param{config}->{'PLUGINHTML'} ;
    eval "use $api;"; 
    my $session =$api->get(%_param) ;
#    bless $session, $class;
    return $session;


}
package Lemonldap::Handlers::Session ;

sub  get {
    my $class= shift;
     my %_param = @_;
    $_param{config}->{'PLUGINBACKEND'}= 'Lemonldap::Handlers::Memsession'    unless $_param{config}->{'PLUGINBACKEND'} ; 
     my $api = $_param{config}->{'PLUGINBACKEND'} ;
    eval "use $api;"; 
    my $html =$api->get(%_param) ;
#    bless $session, $class;
    return $html;
  } 

package Lemonldap::Handlers::Policy ;

sub  get {
    my $class=shift;
    my %_param = @_;
    $_param{parameters}->{config}->{'PLUGINPOLICY'}= 'Lemonldap::Handlers::MatrixPolicy'    unless $_param{parameters}->{config}->{'PLUGINPOLICY'} ;
    my $api = $_param{parameters}->{config}->{'PLUGINPOLICY'} ;
    eval "use $api;" ;;
    my $trust =$api->get(%_param) ;
    #  bless $trust , $class; 
   return $trust;
  } 
package Lemonldap::Handlers::Header ;
sub  get {
    my $class=shift;
    my %_param = @_;
    $_param{config}->{'PLUGINHEADER'}= 'Lemonldap::Handlers::AuthorizationHeader' unless $_param{config}->{'PLUGINHEADER'} ;
    my $api = $_param{config}->{'PLUGINHEADER'} ;
    eval "use $api;"; 
    my $header =$api->get(%_param) ;
    # bless $header , $class; 
   return $header;
  } 
sub  forge {
    my $class=shift;
    my %_param = @_;
    $_param{config}->{'PLUGINHEADER'}= 'Lemonldap::Handlers::AuthorizationHeader' unless $_param{config}->{'PLUGINHEADER'} ;
    my $api = $_param{config}->{'PLUGINHEADER'} ;
    eval "use $api;"; 
    my $header =$api->forge(%_param) ;
    # bless $header , $class; 
   return $header;
  } 

  


1;
