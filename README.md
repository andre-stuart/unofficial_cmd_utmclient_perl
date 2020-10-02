[![GitHub license](https://img.shields.io/github/license/andre-stuart/unofficial_cmd_utmclient_perl)](https://github.com/andre-stuart/unofficial_cmd_utmclient_perl/blob/master/LICENSE) &nbsp; 
[![Perl Version](https://img.shields.io/badge/Perl-v5.26.3-blue)]() &nbsp;
[![Moba Version](https://img.shields.io/badge/MobaXterm-v20.2-blue)]() &nbsp;
[![Windows Version](https://img.shields.io/badge/Windows-10-blue)]()

# unofficial_cmd_utmclient_perl
Unofficial CMD Client for Blockbit® UTM [perl 6]

## Dependency
- libwww-perl
- perl-LWP-Protocol-https

## Instructions
Tested in MobaXterm (https://mobaxterm.mobatek.net/) on Windows 10;

```bash
$ apt-get install perl -y
$ apt-get install perl-libwww-perl -y
$ apt-get install perl-LWP-Protocol-https -y
$ perl utmauth.pl --help

Unofficial command line client for authentication in Blockbit® UTM
Version 0.1
Using:
  utmauth.exe --action[ACTION] --server[ip/host] --login[login/email] --pass[password]

Options:
  --help                -> Show this help message.
  --action[ACTION]      -> [Optional] login, logout, keepalive or status [default: login]. ex: login
  --server[ip/host]     -> [Required] UTM server ip or host. ex: utm.exmaple.com
  --port[port]          -> [Optional] UTM server port [default: 9803]. ex: 9803
  --login[login/email]  -> [Required] UTM login or login@domain. ex: user@exmaple.com
  --pass[password]      -> [Required] UTM user password.
  --agent[uri]          -> [Optional] Client ID user agent [default: CMDClient/[version]].
  --cookie[uri]         -> [Optional] Uri cookie file [default: ./utmauth.cookie]. ex: c:\utmauth.cookie

Example:
  > perl utmauth.pl --action login --server utm.example.com --login user@domain.com --pass "*******"
  > perl utmauth.pl --action logout --server utm.example.com --login user@domain.com
  > perl utmauth.pl --action keepalive --server utm.example.com --login user@domain.com

Developer by Andre StuartDev [nbbr.andre@gmail.com]

Blockbit® is a registered trademark of BLOCKBIT TECNOLOGIA LTDA [https://www.blockbit.com/about/]
```

## Credits

- Blockbit® is a registered trademark of BLOCKBIT TECNOLOGIA LTDA [https://www.blockbit.com/];
- LWP::UserAgent - Web user agent class [https://github.com/libwww-perl/libwww-perl];
- LWP::Protocol::https - Provide https support for LWP::UserAgent [https://github.com/libwww-perl/LWP-Protocol-https]
