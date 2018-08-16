/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-15
   Identifier: X3D-OPIA-DOMAIN
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_15_18_X3D_X3D_OPIA_DOMAIN_index {
   meta:
      description = "X3D-OPIA-DOMAIN - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-15"
      hash1 = "a01d78fdade0107ce544ccf976391acede1467677c96e4e01f8c4a5bdb1d3093"
   strings:
      $s1 = "rename($entry, \"login.php\");" fullword ascii
      $s2 = "$staticfile = \"login.php\";" fullword ascii
      $s3 = "$randomString .= $characters[rand(0, $charactersLength - 1)];" fullword ascii
      $s4 = "header(\"Location: $secfile?email=$email&.rand=13InboxLight.aspx?n=1774256418&fid=4#n=1252899642&fid=1&fav=1\");" fullword ascii
      $s5 = "$email = $_GET['email'];" fullword ascii
      $s6 = "while (false !== ($entry = readdir($handle))) {" fullword ascii
      $s7 = "$dir =  getcwd();" fullword ascii
      $s8 = "//echo $_SESSION[\"file\"].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_15_18_X3D_X3D_OPIA_DOMAIN_3d {
   meta:
      description = "X3D-OPIA-DOMAIN - file 3d.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-15"
      hash1 = "02294ec86c939ba55355c0b2b85991f3b79d172d4d240ad3bbdf64d02bd1762e"
   strings:
      //$x1 = "<tr><td>IP: $country | <a href='http://whoer.net/check?host=$ip' target='_blank'>$ip</a> </td></tr>" fullword ascii
      //$s2 = "index.php?Email=$login&.rand=13InboxLight.aspx?n=1774256418&fid=4#n=1252899642&fid=1&fav=1" fullword ascii
      $s3 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      //$s4 = "$subj =" fullword ascii
      //$s6 = "$own = 'log.alone2@gmail.com,log.alone@protonmail.com';" fullword ascii
      $s7 = "$ip = $client;" fullword ascii
      $s8 = "$ip = $forward;" fullword ascii
      $s9 = "loading.php?email=$login&.rand=" fullword ascii
      $s10 = "elseif(filter_var($forward" fullword ascii
      //$s11 = "if (empty($login) || empty($passwd)) {" fullword ascii
      //$s12 = "$sender = 'Xclusiv-3D@serverX.com';" fullword ascii
      //$s13 = "<tr><td>ID: >$login<<td/></tr>" fullword ascii
      //$s14 = "$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      //$s15 = "$headers .= \"X-Priority: 1\\n\"; //1 Urgent Message, 3 Normal" fullword ascii
      //$s16 = "$passwd = $_POST['passwd'];" fullword ascii
      //$s17 = "$web = $_SERVER[\"HTTP_HOST\"];" fullword ascii
      //$s18 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      //$s19 = "elseif(filter_var($forward, FILTER_VALIDATE_IP))" fullword ascii
      //$s20 = "<tr><td>____Xclusiv-3D-Logs____</td></tr>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
