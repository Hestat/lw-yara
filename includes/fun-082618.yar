/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-26
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_26_18_shell_fun {
   meta:
      description = "shell2 - file fun.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "9d095e4f6a3f37c46a1aac4704da957c92fbde23feea3cfd1a0693522e3a73a8"
   strings:
      $s1 = "<?php /* Only For NassRawi , X-SHADOW" fullword ascii
      $s2 = "$OOO000000=urldeCode('" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( all of them )
      ) or ( all of them )
}
