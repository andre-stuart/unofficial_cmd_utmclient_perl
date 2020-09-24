use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;
use Data::Dumper;

use constant {
    SUCCESS => 0,
    ERR_UNKNOW => -1,
    ERR_PARAM => -2,
    ERR_CONN => -3,
    ERR_AUTH => -4
};

Help() and exit ERR_PARAM if(scalar @ARGV < 1);

my ($action, $server, $port, $login, $pass, $agent, $cookie);

my $size = scalar @ARGV;
for(my $i = 0 ; $i < $size; $i++)
{
    my $iv = $i + 1;

    Help() and exit SUCCESS if ($ARGV[$i] eq "--help");

    next if($ARGV[$i] !~ m/--/);

    $action = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--action" && $ARGV[$iv] !~ m/--/ );
    $server = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--server" && $ARGV[$iv] !~ m/--/ );
    $port = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--port" && $ARGV[$iv] !~ m/--/ );
    $login = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--login" && $ARGV[$iv] !~ m/--/ );
    $pass = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--pass" && $ARGV[$iv] !~ m/--/ );
    $agent = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--agent" && $ARGV[$iv] !~ m/--/ );
    $cookie = Trim( lc $ARGV[$iv] ) and next if ($ARGV[$i] eq "--cookie" && $ARGV[$iv] !~ m/--/ );

    print STDERR "Invalid parameter" and exit ERR_PARAM;
}

print STDERR "Login or server parameter invalid\n" and exit ERR_PARAM if (!$server || !$login);

$action = "login" if not $action;
$port = "9803" if not $port;
$agent = "CMDClient" if not $agent;
$cookie = "utmauth.cookie" if not $cookie;

print STDERR "Action parameter invalid\n" and exit ERR_PARAM if (!IsAction($action));
print STDERR "Server parameter invalid\n" and exit ERR_PARAM if (!IsServer($server) || length $server > 253);
print STDERR "Port parameter invalid\n" and exit ERR_PARAM if (!IsPort($port));
print STDERR "Login parameter invalid\n" and exit ERR_PARAM if (!IsLogin($login) || length $login > 320);
print STDERR "Pass parameter invalid\n" and exit ERR_PARAM if ($action eq "login" && !$pass);
print STDERR "Agent parameter invalid\n" and exit ERR_PARAM if (!IsName($agent) || length $agent > 200);
print STDERR "Cookie parameter invalid\n" and exit ERR_PARAM if (length $agent > 1024);

my $url = "https://$server:$port/authd.fcgi";
my $data = "Action=AUTH_LOGIN";
$data .= "&Login=" . unpack("H*", $login);
$data .= "&Password=" . unpack("H*", $pass);
$data .= "&UserAgent=" . unpack("H*", $agent);

local $ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

my $req = HTTP::Request::Common::POST($url, Content => $data);
my $ua = LWP::UserAgent->new;
my $res = $ua->request($req);

open(COOKIE,">",$cookie) or die "Cookie parameter invalid\n";

if(!$res || $res->code != "200")
{
    print COOKIE "";
    close(COOKIE);
    print STDERR "error " . $res->code . " " . $res->message . "\n";
    exit ERR_CONN;
}

print STDOUT $res->content . "\n";
print COOKIE $res->content;
close(COOKIE);

exit SUCCESS;

# Functions --------------------
sub Help {
    print STDOUT ("\n");
    print STDOUT ("Unofficial command line client for authentication in Blockbit® UTM\n");
    print STDOUT ("Version 0.1\n");
    print STDOUT ("Using:\n");
    print STDOUT ("  utmauth.exe --action[ACTION] --server[ip/host] --login[login/email] --pass[password]\n");
    print STDOUT ("\n");
    print STDOUT ("Options:\n");
    print STDOUT ("  --help                -> Show this help message.\n");
    print STDOUT ("  --action[ACTION]      -> [Optional] login, logout, keepalive or status [default: login]. ex: login\n");
    print STDOUT ("  --server[ip/host]     -> [Required] UTM server ip or host. ex: utm.exmaple.com\n");
    print STDOUT ("  --port[port]          -> [Optional] UTM server port [default: 9803]. ex: 9803\n");
    print STDOUT ("  --login[login/email]  -> [Required] UTM login or login\@domain. ex: user\@exmaple.com\n");
    print STDOUT ("  --pass[password]      -> [Required] UTM user password.\n");
    print STDOUT ("  --agent[uri]          -> [Optional] Client ID user agent [default: CMDClient/[version]].\n");
    print STDOUT ("  --cookie[uri]         -> [Optional] Uri cookie file [default: ./utmauth.cookie]. ex: c:\\utmauth.cookie\n");
    print STDOUT ("\n");
    print STDOUT ("Example:\n");
    print STDOUT ("  > perl utmauth.pl --action login --server utm.exmaple.com --login user\@exmaple.com --pass \"*******\"\n");
    print STDOUT ("  > perl utmauth.pl --action logout --server utm.exmaple.com --login user\@exmaple.com\n");
    print STDOUT ("  > perl utmauth.pl --action keepalive --server utm.exmaple.com --login user\@exmaple.com\n");
    print STDOUT ("\n");
    print STDOUT ("Developer by Andre StuartDev [nbbr.andre\@gmail.com]\n");
    print STDOUT ("\n");
    print STDOUT ("Blockbit® is a registered trademark of BLOCKBIT TECNOLOGIA LTDA [https://www.blockbit.com/about/]\n");
}

sub Trim { 
    my $s = shift; 
    $s =~ s/^\s+|\s+$//g; 
    $s =~ tr/\r\n//d;
    return $s 
};

sub IsName { my $s = shift; return $s =~ m/^[a-zA-Z0-9_.-]*$/; }
sub IsAction { my $s = shift; return ($s eq "login" || $s eq "logout" || $s eq "keepalive"); }
sub IsServer { my $s = shift; return ($s =~ m/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/ || $s =~ m/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$/); }
sub IsPort { my $s = shift; return $s =~ m/^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$/; }
sub IsLogin { my $s = shift; return ($s =~ m/^(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)$/ || $s =~ m/^[a-zA-Z0-9_.-]*$/); }