/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-03
   Identifier: phish
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_03_18_phishing_index {
   meta:
      description = "phish - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-03"
      hash1 = "15b84d95651fa23226d0198fe6fa3d0671221f4a5c44677358c8b125b6667a5a"
   strings:
      $s2 = "$login = $_GET['email'];" fullword ascii
      $s3 = "rename($entry, \"login.php\");" fullword ascii
      $s4 = "$staticfile = \"login.php\";" fullword ascii
      $s5 = "$randomString .= $characters[rand(0, $charactersLength - 1)];" fullword ascii
      $s6 = "header(\"Location: $secfile?rand=13InboxLightaspxn.1774256418&fid.4.1252899642&fid=1&fav.1&rand.13InboxLight.aspxn.1774256418&fi" ascii
      $s7 = "while (false !== ($entry = readdir($handle))) {" fullword ascii
      $s8 = "$dir =  getcwd();" fullword ascii
      $s9 = "//echo $_SESSION[\"file\"].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_09_03_18_phish_server {
   meta:
      description = "phish - file server.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-03"
      hash1 = "1c9066dd9b1d91a0cc9278629f7f0f8c7a6b9f9e0ebb1e739dd210f7a03ec025"
   strings:
      $s1 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      $s2 = "mail($own,$subj,$msg,$headers);" fullword ascii
      $s3 = "<?php"
   condition:
       ( all of them )
}

