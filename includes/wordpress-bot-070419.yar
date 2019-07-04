/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-07-04
   Identifier: 07-04-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule wordpress_bot2 {
   meta:
      description = "07-04-19 - file wordpress-bot2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-07-04"
      hash1 = "a0fa8c69341cd91679d06a576772d5154b9318a84f46f88acfb49490b678df6d"
   strings:
      $s1 = "goto XljGS; nMNd4: $Y_JLM = file_get_contents(trim($rOWLw)); goto jRAr_; qUhpk: echo \"\\141\\x75\\x78\\x36\\x54\\150\\x65\\151" ascii
      $s2 = "1c; iCbpx: exec($pgcps); goto DJ29v; qgWl4: if (!($_POST[\"\\x63\\160\"] == \"\\x64\\157\\167\\156\\x6c\\x6f\\141\\x64\")) { got" ascii
      $s3 = "XdH2U: qtfL9: goto UA1tk; XljGS: error_reporting(0); goto e2htE; o6j1c: $rOWLw = $_POST[\"\\165\\162\\154\"]; goto k5Ofv; jRAr_:" ascii
      $s4 = "goto XljGS; nMNd4: $Y_JLM = file_get_contents(trim($rOWLw)); goto jRAr_; qUhpk: echo \"\\141\\x75\\x78\\x36\\x54\\150\\x65\\151" ascii
      $s5 = "$aXH4D); goto RC55t; DJ29v: echo \"\\x6f\\153\"; goto XdH2U; UA1tk: hr6VR:" fullword ascii
      $s6 = "\\156\\165\\154\\154\\x20\\x32\\76\\x2f\\x64\\145\\166\\57\\x6e\\x75\\x6c\\x6c\\x20\\46\"; goto iCbpx; GwGpj: exec(\"\\160\\153" ascii
      $s7 = "o qUhpk; RC55t: exec(\"\\x70\\153\\151\\154\\154\\x20\\x2d\\x39\\40\\x2d\\146\\x20\\x73\\x74\\145\\x61\\154\\164\\150\"); goto G" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

rule wordpress_bot1 {
   meta:
      description = "07-04-19 - file wordpress-bot1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-07-04"
      hash1 = "6a6eac7d84738c14320d18d43b8806a1f1c58b2e7693a9320ef97d89c3847527"
   strings:
      //$s1 = "\" . \"\\145\" . '' . \"\\162\" . \"\\x63\" . '' . ''); goto gCXGN; OMTcw: $zWk0S();" fullword ascii
      $s2 = "<?php"
      $s3 = "goto Foltw"
      $s4 = "$SsrUL < strlen($d38Ix)"
      $s5 = "foreach"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

