/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell5
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_shell_ups {
   meta:
      description = "shell5 - file ups.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "895b6d730863e3b244755537628b3ad42801207efd6746c88f3b50c7da45fd04"
   strings:
      $s1 = "<?php move_uploaded_file($_FILES[f][tmp_name],$_FILES[f][name]);?>" fullword ascii
   condition:
      ( uint16(0) == 0x3131 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
