/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_24_18_shell_eg {
   meta:
      description = "shell2 - file eg.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
      hash1 = "3f55f02534ce2641fbd0750c4a07bd8b3aa15867def2003f00b8a5fe9ef1236a"
   strings:
      $s1 = "<style>body{overflow:hidden;background-color:black}#q{font:40px impact;color:white;position:absolute;left:0;right:0;top:43%}" fullword ascii
      $s2 = "<?php if(isset($_GET[\"qnqnr\"])){echo\"<font color=#FFFFFF>[uname]\".php_uname().\"[/uname]\";echo\"<form method=post enctype=m" ascii
      $s3 = ".$_FILES[\"f\"][\"name\"];}else{echo\"<b>gagal" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_24_18_shell_xx_gif {
   meta:
      description = "shell2 - file xx.gif"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
      hash1 = "5c5ed56fe1ee4b4d0d8f13738ab5dbbc50b6f072214c929dc09c9c1653efb846"
   strings:
      $s1 = "$randomS .= $characters[rand(0, strlen($characters) - 1)];" fullword ascii
      $s2 = "<style>body{overflow:hidden;background-color:black}#q{font:40px impact;color:white;position:absolute;left:0;right:0;top:43%}';" fullword ascii
      $s3 = "$file .= '<title>Hacked by Dr.SiLnT HilL</title><center><div id=q>AnonymousFox<br><font size=2>" fullword ascii
      $s4 = "$r=fopen(\"eg.php\", \"w\");fwrite($r,$file);fclose($r);" fullword ascii
      $s5 = "$r=fopen(\"../../tmp/eg.php\", \"w\");fwrite($r,$file);fclose($r);" fullword ascii
      $s6 = "$r=fopen(\"x.php\", \"w\");fwrite($r,\"\");fclose($r);" fullword ascii
      $s7 = "$file  = '<?php if(isset($_GET[\"'.$ndom.'\"])){echo\"<font color=#FFFFFF>[uname]\".php_uname().\"[/uname]\";echo\"<form method=" ascii
      $s8 = "$r=fopen(\"../tmp/eg.php\", \"w\");fwrite($r,$file);fclose($r);" fullword ascii
      $s9 = "if(file_exists(\"x.php\")) unlink(\"x.php\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

