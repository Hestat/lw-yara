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
      $s13 = "freecontent.bid"
      $s14 = "freecontent.date"
      $s15 = "freecontent.faith"
      $s16 = "freecontent.party"
      $s17 = "freecontent.science"
      $s18 = "freecontent.stream"
      $s19 = "freecontent.trade"
      $s20 = "hostingcloud.accountant"
      $s21 = "hostingcloud.bid"
      $s22 = "hostingcloud.date"
      $s23 = "hostingcloud.download"
      $s24 = "hostingcloud.faith"
      $s25 = "hostingcloud.loan"
      $s26 = "jshosting.bid"
      $s27 = "jshosting.date"
      $s28 = "jshosting.download"
      $s29 = "jshosting.loan"
      $s30 = "jshosting.party"
      $s31 = "jshosting.racing"
      $s32 = "jshosting.review"
      $s33 = "jshosting.stream"
      $s34 = "jshosting.trade"
      $s35 = "jshosting.win"

   condition:
      any of them
}

