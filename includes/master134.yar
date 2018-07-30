/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-30
   Identifier: Master134
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule Master134_Malvertising {
   meta:
      description = "Master134 file index.html"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      reference = "https://research.checkpoint.com/malvertising-campaign-based-secrets-lies/"
      date = "2018-07-30"
   strings:
      $s1 = "var _0xaae8=[" fullword ascii
      $s2 = "document[_0"
   condition:
      all of them
}

