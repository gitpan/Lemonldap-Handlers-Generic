package Lemonldap::Handlers::Error ;
use Apache::Constants qw (:common);
sub handler {
	my $r = shift;
         my $uri = $r->uri;
my ($application) = $uri=~ /\/.+\/(.+)\.html/ ;

$r->content_type('text/html');
$r->send_http_header;
$r->print(<<END);
<html>
<head><title>lemonldap websso</title></head>
<body>
<h1>Lemonldap websso</h1>
<h4>Error  on $application </h4>
<h4> Reason : You don't have any access on this application</h4>
</body>
</html>
END

 return OK;
}




 
