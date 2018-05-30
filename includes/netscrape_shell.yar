/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-30
   Identifier: case113
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule netscrape_shell {
   meta:
      description = "case113 - file netscrape-shell.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-30"
      hash1 = "63e43355854f640a1f81033042162d356d4af8a6bf9d327e27c4ac8ce366f740"
   strings:
      $x1 = "$str = \"host='\" . $ip . \"' port='\" . $port . \"' user='\" . $login . \"' password='\" . $pass . \"' dbname=postgres\";" fullword ascii
      $x2 = "\"findconfig * files\" => \"find / -typef - name\\\"config*\\\"\", \"find config* files in current dir\" => \"find . -type f -na" ascii
      $x3 = "echo '<h1>Bruteforce</h1><div class=content><table><form method=post><tr><td><span>Type</span></td>' . '<td><select name=proto><" ascii
      $x4 = "if (is_file($_POST['p1'])) $m = array('View', 'Highlight', 'Download', 'Hexdump', 'Edit', 'Chmod', 'Rename', 'Touch');" fullword ascii
      $x5 = "if ($db->connect($_POST['sql_host'], $_POST['sql_login'], $_POST['sql_pass'], $_POST['sql_base'])) {" fullword ascii
      $x6 = "if (!isset($_COOKIE[md5($_SERVER['HTTP_HOST']) ]) || ($_COOKIE[md5($_SERVER['HTTP_HOST']) ] != $auth_pass)) wsoLogin();" fullword ascii
      $x7 = ". ' < td > < nobr > ' . substr(@php_uname(), 0, 120) . ' < ahref = \"' . $explink . '\"target = _blank > [exploit - db . co" fullword ascii
      $s8 = "die(\"<pre align=center><form method=post>Password: <input type=password name=pass><input type=submit value='>>'></form><" fullword ascii
      $s9 = "$db->connect($_POST['sql_host'], $_POST['sql_login'], $_POST['sql_pass'], $_POST['sql_base']);" fullword ascii
      $s10 = "if ($this->link = @pg_connect(\"host={$host[0]} port={$host[1]} user=$user password=$pass dbname=$dbname\")) return true;" fullword ascii
      $s11 = "foreach ($downloaders as $item) if (wsoWhich($item)) $temp[] = $item;" fullword ascii
      $s12 = "if (isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass)) WSOsetcookie(md5($_SERVER['HTTP_HOST']), $auth_pass);" fullword ascii
      $s13 = "$downloaders = array('wget', 'fetch', 'lynx', 'links', 'curl', 'get', 'lwp-mirror');" fullword ascii
      $s14 = "if (empty($_POST['ajax']) && !empty($_POST['p1'])) WSOsetcookie(md5($_SERVER['HTTP_HOST']) . 'ajax', 0);" fullword ascii
      $s15 = "$downloaders = array('wget', 'fetch', 'lynx', 'links', 'curl', 'get', 'l" fullword ascii
      $s16 = "$explink = 'http://exploit-db.com/search/?action=search&filter_description=';" fullword ascii
      $s17 = "wsoSecParam('Downloaders', implode(', ', $temp));" fullword ascii
      $s18 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST['charset'] . \"'><title>\" . " fullword ascii
      $s19 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=post on" fullword ascii
      $s20 = "if ($db->connect($_POST['sql_host'], $_POST['sql_login']" fullword ascii
   condition:
      ( uint16(0) == 0x7263 and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _infected_05_30_18_obfuscated_netscrape_shell {
   meta:
      description = "case113 - file -.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-30"
      hash1 = "5c05b22d161a82c30f63426a6c161ddbbd47d7acf867e9c5958ccb682be5a720"
   strings:
      $s1 = "$c0000101101010001010101101111110110101010111111111110101010101sdc0s1dc0sd1c0s1dc0s1d0cs1d0cs1dcsdc1sdc1s0dc1sd0cs1dc0s1dcs1d1g0" ascii
      $s2 = "dyrUnWXdzU9Ml9J0jOvB2bxvXGQkadeufKUvqOFFl8fqEo2EqI2v3QYBVaiYoiCDsw7dHEcipftIeyUcmMs1R1k5Pnvhl757hM0fQdD/pjjyFTP2vuw8xLDtAVrGcpGn" ascii
      $s3 = "MahWyawtVOtzh7WH7J6x3QnQb87tiUV+BN+iXzx9VNn07OoG2hjgdqh6zphJ2mmaWj74OwMyyWZkNwhAM+u1s2sbPClE34JVH2cTh0/mocSBLLpeyeO5pFfQRLnwTQaa" ascii
      $s4 = "2DDsNfthY3Rx+U7W/NijJE6rXEWSER4jumqzPfMMbWavn+VCHod6jp8mx1iH+2/fn7csuf92I9tgetGwUiQRAKblyzS2Mnq+Bw97C4GN/hAd9nTql9HuNeQpfsgowZwr" ascii
      $s5 = "nalanBEDllYrCJFnN6uyubiHhnl9chV9IghzN3WKaPcQbGMB4n/h212Z4deGpm99F0y8e5E8gDpV+rxUOrbRaA8tqlaSZ9hiaP2pDfraOhbuUXlbJiC8SgAsYQQXxUIE" ascii
      $s6 = "8/DCcYoPDgPm0HHXwqAW6tMPP5hYaYl7wLjD2XlqFiRzlKNFEqNB4/Hj6KoRKuAdvGgpwkyrVDNT4l6CH5gjqNeKAVmI/6SW4rsFZn5zJ10+vNTWhcV3U1SjZh181JdQ" ascii
      $s7 = "KPrZEslUzhQ+rrX2E/k2zgqBBMPbavzCF05ZvGbnCVGe4q/p/OFgwbInGVBdo5PdmAxRhORkeAKAEjtXD5S0Jz6jXJnwFZV89GEjX5/68T0/F953Dui4F92mzbB/jcbm" ascii
      $s8 = "HjmG/Va7vEKHywKL+Bn46tywk/neL6spXKhWTDoUffFtQwGuRuN3hcGHDQas5/Gk1SbGRvKQo8eTipiGjrv1mygeFo3RDf0FmjhcHeh66TVNh1CrQYklWFs2wT4S4pTr" ascii
      $s9 = "cAQ5mEZIM+bn3jChEqvb0TlCWTvnvAdCW+QpMu26HdhZFux5cyFLV7u7OLggW9tewsEQlObf8uGvSQimTAYglHV98NaWoDLl/1OTQdMjXHT+qaNuNNTc2FSnkJxJePI6" ascii
      $s10 = "/* Smart Tools Shop v5*/" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

