/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: case139
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule case139_main_js_malvertising {
   meta:
      description = "case139 - file main.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "365243ff6b56a628a28d5b1bb0823dcb3192c5dec7fea94bd72b00709252e66a"
   strings:
      $s1 = "eval(String.fromCharCode(9, 105," fullword ascii
   condition:
      ( uint16(0) == 0x7665 and
         filesize < 8KB and
         ( all of them )
      ) or ( all of them )
}

