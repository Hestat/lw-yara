/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-21
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_21_18_shell2_shell_test {
   meta:
      description = "shell - file test.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-21"
      hash1 = "f48a75ca4c418e39f0b1a81476a6a05c02c22d68a28f93eec503307adec81cf6"
   strings:
      $s1 = "print \"<b>send an report to [\".$_POST['email'].\"] - Order : $xx</b>\"; " fullword ascii
      $s2 = "mail($_POST['email'],\"Result Report Test - \".$xx,\"WORKING !\");" fullword ascii
      //$s3 = "er=\"Order ID\" name=\"orderid\" value=\"<?php print $_POST['orderid']?>\" ><br>" fullword ascii
      $s4 = "if (!empty($_POST['email'])){" fullword ascii
      $s5 = "$xx =$_POST['orderid'];" fullword ascii
      $s6 = "Upload is <b><color>WORKING</color></b><br>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
