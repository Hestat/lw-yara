/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-01
   Identifier: botnet-kit
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_09_01_18_botnet_kit_index {
   meta:
      description = "botnet-kit - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-01"
      hash1 = "3653e310cd3937134ad1b7dcfe3e9b2e6fba37800d0dd9bbfec189ae4a3e38c3"
   strings:
      $s1 = "<script src=\"http://code.jquery.com/jquery.js\"></script>" fullword ascii
      $s2 = "$sessionTime = 5; //this is the time in **minutes** to consider someone online before removing them from our file" fullword ascii
      $s3 = "header(\"Location: login.php\");" fullword ascii
      $s4 = "$users[] = rtrim(fgets($fp, 32));" fullword ascii
      $s5 = "$fh = fopen(\"target.port\", 'w+');" fullword ascii
      $s6 = "if(time() - $lastvisit >= $sessionTime * 60) {" fullword ascii
      $s7 = "<title>LOLZTEAM.COM | Blue Botnet CPANEL</title>" fullword ascii
      $s8 = "$filename = \"target.port\";" fullword ascii
      $s9 = "foreach($users as $key => $data) {" fullword ascii
      $s10 = "<!-- jQuery e plugin JavaScript  -->" fullword ascii
      $s11 = "$fh = fopen(\"target.method\", 'w+');" fullword ascii
      $s12 = "$fh = fopen(\"target.ip\", 'w+');" fullword ascii
      $s13 = "$content = fread($fp, filesize($filename));" fullword ascii
      $s14 = "<form action=\"index.php\" method=\"post\">" fullword ascii
      $s15 = "$users[$x] = \"$ip|\" . time(); //updating" fullword ascii
      $s16 = "$fh = fopen(\"target\", 'w+');" fullword ascii
      $s17 = "$filename = \"target.method\";" fullword ascii
      $s18 = "<li><a href=\"logout.php\">Logout</a></li>" fullword ascii
      $s19 = "$filename = \"target.ip\";" fullword ascii
      $s20 = "<link href=\"css/stili-custom.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_01_18_botnet_kit_botlogger {
   meta:
      description = "botnet-kit - file botlogger.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-01"
      hash1 = "2aceed18868bb5e8660869606517a7bc703906435cc47bba13445bd0ee2b7961"
   strings:
      $s1 = "$sessionTime = 5; //this is the time in **minutes** to consider someone online before removing them from our file" fullword ascii
      $s2 = "$users[] = rtrim(fgets($fp, 32));" fullword ascii
      $s3 = "if(time() - $lastvisit >= $sessionTime * 60) {" fullword ascii
      $s4 = "foreach($users as $key => $data) {" fullword ascii
      $s5 = "echo '<div style=\"padding:5px; margin:auto; background-color:#fff\"><b>' . $i . ' visitors online</b></div>';" fullword ascii
      $s6 = "$users[$x] = \"$ip|\" . time(); //updating" fullword ascii
      $s7 = "$users[] = \"$ip|\" . time();" fullword ascii
      $s8 = "foreach($users as $single) {" fullword ascii
      $s9 = "$onusers = array();" fullword ascii
      $s10 = "$users[$x] = \"\";" fullword ascii
      $s11 = "error_reporting(E_ERROR | E_PARSE);" fullword ascii
      $s12 = "$dataFile = \"visitors.txt\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_01_18_botnet_kit_onlinebots {
   meta:
      description = "botnet-kit - file onlinebots.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-01"
      hash1 = "6c741cfb37f2f963df3d3a529648e2430618fd46d0a940b8b68577c687b18d83"
   strings:
      $s1 = "<script src=\"http://code.jquery.com/jquery.js\"></script>" fullword ascii
      $s2 = "$sessionTime = 5; //this is the time in **minutes** to consider someone online before removing them from our file" fullword ascii
      $s3 = "header(\"Location: login.php\");" fullword ascii
      $s4 = "$users[] = rtrim(fgets($fp, 32));" fullword ascii
      $s5 = "$fh = fopen(\"target.port\", 'w+');" fullword ascii
      $s6 = "if(time() - $lastvisit >= $sessionTime * 60) {" fullword ascii
      $s7 = "foreach($users as $key => $data) {" fullword ascii
      $s8 = "<!-- jQuery e plugin JavaScript  -->" fullword ascii
      $s9 = "$fh = fopen(\"target.method\", 'w+');" fullword ascii
      $s10 = "$fh = fopen(\"target.ip\", 'w+');" fullword ascii
      $s11 = "$content = fread($fp, filesize($filename));" fullword ascii
      $s12 = "<form action=\"index.php\" method=\"post\">" fullword ascii
      $s13 = "$users[$x] = \"$ip|\" . time(); //updating" fullword ascii
      $s14 = "<li><a href=\"logout.php\">Logout</a></li>" fullword ascii
      $s15 = "for ($i=0; $i<count($bots) - 1; $i++){" fullword ascii
      $s16 = "<link href=\"css/stili-custom.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
      $s17 = "$storedPassHash = $content;" fullword ascii
      $s18 = "$ip = $_POST['ipaddress'];" fullword ascii
      $s19 = "<!-- respond.js per IE8 -->" fullword ascii
      $s20 = "$ip = $_GET['ipaddress'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}


rule infected_09_01_18_botnet_kit_login {
   meta:
      description = "botnet-kit - file login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-01"
      hash1 = "6d9b953093ceb5af242f4cb813a4c5fe25f03840d31d063d4f90e342e695f4c3"
   strings:
      $s1 = "<form action=\"login.php\" method=\"post\">" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery.js\"></script>" fullword ascii
      $s3 = "$password = $_POST['password'];" fullword ascii
      $s4 = "if (md5(\"randomsalt\".md5($password)) == $storedPassHash){" fullword ascii
      $s5 = "<!-- jQuery e plugin JavaScript  -->" fullword ascii
      $s6 = "<button type=\"submit\" class=\"btn btn-default\">LOGIN</button>" fullword ascii
      $s7 = "<input class=\"form-control\" placeholder=\"password\" type=\"password\" name=\"password\">" fullword ascii
      $s8 = "$content = fread($fp, filesize($filename));" fullword ascii
      $s9 = "setcookie(\"phash\", md5($password));" fullword ascii
      $s10 = "<link href=\"css/stili-custom.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
      $s11 = "<label for=\"IP\">PASSWORD</label>" fullword ascii
      $s12 = "$storedPassHash = $content;" fullword ascii
      $s13 = "<!-- respond.js per IE8 -->" fullword ascii
      $s14 = "<link href=\"css/bootstrap.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
      $s15 = "<script src=\"js/respond.min.js\"></script>" fullword ascii
      $s16 = "<script src=\"js/bootstrap.min.js\"></script>" fullword ascii
      $s17 = "<!-- Fogli di stile -->" fullword ascii
      $s18 = "<!-- Modernizr -->" fullword ascii
      $s19 = "error_reporting(E_ERROR | E_PARSE);" fullword ascii
      $s20 = "if ($password != \"\"){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}

