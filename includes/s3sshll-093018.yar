/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_s3sshll {
   meta:
      description = "shell1 - file s3sshll.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "1f43f36274d83c0c7c1cbd5e9017dfc2a9326829deaced88d49900c2d897d9ea"
   strings:
      $s1 = "$chk_login" ascii
      $s2 = "$password" ascii
      $s3 = "if(!function_exists("
      $s4 = "base64_decode"
      $s5 = "preg_match("
      $s6 = "<?php"
   condition:
         ( all of them )
}

