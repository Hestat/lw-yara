/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-31
   Identifier: case114
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_day_uploader_shell {
   meta:
      description = "case114 - file 9st48vlvfp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-31"
      hash1 = "6452039c95cf77d834e2eaa1459abf4e176c1f7158f2b86751138e5bd24e072e"
   strings:
      $s1 = "str_replace" fullword ascii
      $s2 = "eval (gzinflate(base64_decode" ascii
      $s3 = "eval"
      $s4 = "intval(__LINE__)" fullword ascii
      $s5 = "?php"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( all of them )
      ) or ( all of them )
}

