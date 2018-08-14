/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-14
   Identifier: thumb
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule wp_timthumb_081418 {
   meta:
      description = "thumb - file wp-timthumb.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "d95f9d6ce28e16d1dc67d1bf0cd652f21922611556bead94c0645039be77a9c6"
   strings:
      $s1 = "<?php extract($_COOKIE);@$W(@$X($Y,$Z));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

