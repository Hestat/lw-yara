/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-22
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_22_18_perl_shell_t {
   meta:
      description = "shell - file t"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "670e0f43e3fee8532bd28fa236008527287feadd7ce4c1d46566c23dc634adb8"
   strings:
      $x1 = "\"\\001bitchx-1.0c18 :tunnelvision/1.2\\001\",\"\\001PnP 4.22 - http://www.pairc.com/\\001\"," fullword ascii
      $x2 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312xMap Portscanning\\003\\002: $1 \\002\\00312Ports:\\003\\002 $2-$3\");" fullword ascii
      $x3 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312Portscanning\\003\\002: $1 \\002\\00312Ports:\\003\\002 default\");" fullword ascii
      $x4 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312(UDP Complete):\\003\\002 $1 - \\002Sendt\\002: $pacotese\".\"kb -" fullword ascii
      $s5 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :Port Scan Complete with target: $1 \");" fullword ascii
      $s6 = "$shell = \"cmd.exe\";" fullword ascii
      $s7 = "\"\\001ircII 20050423+ScrollZ 1.9.5 (19.12.2004)+Cdcc v1.8+OperMods v1.0 by acidflash - Almost there\\001\");" fullword ascii
      $s8 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312(Download)\\002\\00314 Page: $2 (File: $1)\") if ($xstats);" fullword ascii
      $s9 = "\"\\001HydraIRC v0.3.148 (18/Jan/2005) by Dominic Clifton aka Hydra - #HydraIRC on EFNet\\001\"," fullword ascii
      $s10 = "\"\\001ircII 20050423+ScrollZ 1.9.5 (19.12.2004)+Cdcc v1.6mods v1.0 by acidflash - Almost there\\001\"," fullword ascii
      $s11 = "\"\\001irssi v0.8.10 - running on Linux i586\\001\",\"\\001irssi v0.8.10 - running on FreeBSD i386\\001\"," fullword ascii
      $s12 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002[x] ->\\0034 Injection ...\");" fullword ascii
      $s13 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");" fullword ascii
      $s14 = "\"\\001BitchX-1.1-final+ by panasync - Linux 2.6.18.1 : Keep it to yourself!\\001\"," fullword ascii
      $s15 = "\"\\001BitchX-1.0c19+ by panasync - Linux 2.4.33.3 : Keep it to yourself!\\001\"," fullword ascii
      $s16 = "my $IRC_socket = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>\"$servidor_con\", PeerPort=>$porta_con) or return(1);" fullword ascii
      $s17 = "system(\"cd /var/tmp ; rm -rf cb find god* wunder* udev* lib*\");" fullword ascii
      $s18 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002\\00312(UDP Complete):\\003\\002 $1 - \\002Sendt\\002: $pacotese\".\"kb - \\002" ascii
      $s19 = "\"\\001ircN 8.00 - he tries to tell me what I put inside of me -\\001\"," fullword ascii
      $s20 = "return _trivial_http_get($host, $port, $path);" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 80KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

