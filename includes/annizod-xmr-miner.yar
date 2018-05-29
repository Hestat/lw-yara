/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-29
   Identifier: case110
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _case110_annizod_XMR_MINER {
   meta:
      description = "case110 - file annizod"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "3c3bbbe6148f052f5d4d28171b55f6d40db65d4ef04822499c5d5e4228c2c557"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "XMRig/%sK libuv" fullword ascii
      $s3 = "xmrig" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

