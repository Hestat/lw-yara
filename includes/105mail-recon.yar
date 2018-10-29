/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://github.com/bediger4000/php-malware-analysis/tree/master/105.71.0.37-2018-05-17a
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_105_71_0_mail_recon {
   meta:
      description = "shells - file 105.71.0.37Wv3QiJz2gZp-SgwzsWNGmAAAABM.0.file"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "e310d4f23aaa3c270190306829ab68e4c57aa5b9b08d856f3518c21582b9f522"
   strings:
      $s1 = "mail($_POST['email'],\"Result Report Test - \".$xx,\"WORKING !\");" fullword ascii
      $s2 = "print \"<b>send an report to [\".$_POST['email'].\"] - $xx</b>\"; " fullword ascii
      $s3 = "<input type=\"text\" name=\"email\" value=\"<?php print $_POST['email']?>\"required >" fullword ascii
      $s4 = "if (!empty($_POST['email'])){" fullword ascii
      $s5 = "Upload is <b><color>WORKING</color></b><br>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
