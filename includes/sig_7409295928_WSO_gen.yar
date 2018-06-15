/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-15
   Identifier: case135
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_7409295928_WSO_generic {
   meta:
      description = "case135 - file 7409295928.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-15"
      hash1 = "b97d6507049bcde47cbe0666675abdb7159a519cbbe5fe97c282f4d6f9d59c16"
   strings:
      $s1 = "?php" ascii
      $s2 = "WSO" ascii
      $s3 = "urldecode" ascii
      //$s4 = "<?php /* WSO [2.6]  */$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$GLOBALS['OOO0000O0']=$OOO0000" ascii
      $s5 = "$GLOBALS" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

