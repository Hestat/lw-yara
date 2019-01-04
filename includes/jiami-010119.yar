/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-03
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_03_19_shell_jiami {
   meta:
      description = "shell - file jiami.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-03"
      hash1 = "96361377d3b4d593397fdbe193af550dd94086c0990cc59c471d449cbf2aa315"
   strings:
      $s1 = "<?php /* PHP Encode by  http://Www.PHPJiaMi.Com/ */error_reporting(0);ini_set(\"display_errors\", 0);if(!defined('adggarmc')){de" ascii
      $s2 = "<?php /* PHP Encode by  http://Www.PHPJiaMi.Com/ */error_reporting(0);ini_set(\"display_errors\", 0);if(!defined('adggarmc')){de" ascii
      $s3 = "WEZBTFBVWV" fullword ascii /* base64 encoded string 'XFALPUY' */
      $s4 = "YZGBUXERY" fullword ascii /* base64 encoded string 'd`T\DX' */
      $s5 = "ZGBUXERYZF" fullword ascii /* base64 encoded string 'd`T\DXd' */
      $s6 = "RHRFLDVESX" fullword ascii /* base64 encoded string 'DtE,5DI' */
      $s7 = "LDRBWVFBPU" fullword ascii /* base64 encoded string ',4AYQA=' */
      $s8 = "LDRAXGBZMU" fullword ascii /* base64 encoded string ',4@\`Y1' */
      $s9 = "ZCRVMGBFVEF" fullword ascii /* base64 encoded string 'd$U0`ETA' */
      $s10 = "ERGVQMTBB" fullword ascii /* base64 encoded string 'DeP10A' */
      $s11 = "FPABIXHRQ" fullword ascii /* base64 encoded string '<H\tP' */
      $s12 = "RVFZRVBHVF" fullword ascii /* base64 encoded string 'EQYEPGT' */
      $s13 = "TUVNPVBZPS1" fullword ascii /* base64 encoded string 'MEM=PY=-' */
      $s14 = "YZGBUXERYZE1" fullword ascii /* base64 encoded string 'd`T\DXdM' */
      $s15 = "VXV1FLWVIJDVFXWE" fullword ascii /* base64 encoded string ']]E-eH$5E]a' */
      $s16 = "AZFRJRVVYQH1" fullword ascii /* base64 encoded string 'dTIEUX@}' */
      $s17 = "OUZLW1RMQF" fullword ascii /* base64 encoded string '9FK[TL@' */
      $s18 = "XC1YQWF5NR" fullword ascii /* base64 encoded string '\-XAay5' */
      $s19 = "PD44P0Q6O2" fullword ascii /* base64 encoded string '<>8?D:;' */
      $s20 = "Q1REN2FTL1Z" fullword ascii /* base64 encoded string 'CTD7aS/V' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 2 of them )
      ) or ( all of them )
}
