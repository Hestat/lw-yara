/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-27
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_27_18_uploader {
   meta:
      description = "shell1 - file up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-27"
      hash1 = "ec5929822e2bcb6d747b24dc42f59beafc0eeb788626ca238d9f092ddd3b3ae2"
   strings:
      $s1 = "$fullpath" fullword ascii
      $s2 = "if (move_uploaded_file($files['tmp_name'], $fullpath)) {" fullword ascii
      $s3 = "if ($files" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

