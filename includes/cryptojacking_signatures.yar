/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: case139
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule crypto_jacking_signatures {
   meta:
      description = "case139 - file main.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
   strings:
      $s1 = "coinhive.min.js"
      $s2 = "wpupdates.github.io/ping"
      $s3 = "cryptonight.asm.js"
      $s4 = "coin-hive.com"
      $s5 = "jsecoin.com"
      $s6 = "cryptoloot.pro"
      $s7 = "webassembly.stream"
      $s8 = "ppoi.org"
      $s9 = "xmrstudio"
      $s10 = "webmine.pro"
      $s11 = "miner.start"
      $s12 = "allfontshere.press"
   condition:
      any of them
}

