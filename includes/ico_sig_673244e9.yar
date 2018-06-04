/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-04
   Identifier: case114
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_673244e9 {
   meta:
      description = "case114 - file 673244e9.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "b2a38e10d833b2bab7d8b73d956258a0c57da0bfad94ca352bdd139a9f4ae746"
   strings:
      $s1 = "?php" fullword ascii
      $s2 = "basename" fullword ascii
      $s3 = "preg_replace"
      $s4 = "rawurldecode"
      $s5 = "trim"
      $s6 = "__FILE__"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( all of them )
      ) or ( all of them )
}

