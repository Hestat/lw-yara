/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: case23
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_case23_db {
   meta:
      description = "case23 - file db.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "95ecc987c604678d86a67944a2d90b341761f0068e98b76752b6310dfaaa4c49"
   strings:
      $s1 = "<?php ${\"\\x47\\x4cOB\\x41\\x4cS\"}[\"\\x68\\x76\\x72\\x74x\\x69\"]=\"\\x61\\x75th\";${\"\\x47\\x4c\\x4f\\x42AL\\x53\"}[\"l\\x7" ascii
      $s2 = "]==\"\\x65\"){$mwvvynwbxyi=\"\\x64\\x61\\x74\\x61\";eval(${$mwvvynwbxyi}[\"\\x64\"]);}exit();}" fullword ascii
      $s3 = "61\\x74\\x61\";function sh_decrypt($data,$key){global$auth;$vuuogtpxiqk=\"\\x61u\\x74\\x68\";return sh_decrypt_phase(sh_decrypt_" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( all of them )
      ) or ( all of them )
}

