/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: miners
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule case25_miners_shared {
   meta:
      description = "miners - file shared"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "9e69143530f6ccb30f813f3d9f0b5dfb51779999dcfe06784d2720ad057d8316"
   strings:
      $s1 = "2526272829" ascii /* hex encoded string '%&'()' */
      $s2 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s3 = "RkeyedWo" fullword ascii
      $s4 = "failures" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

rule case25_miners_kserviced {
   meta:
      description = "miners - file kserviced"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "6c9b44df7caa65cb7f652f411b38f8b49564e3ae265aa75a2c6d0acda22ea20f"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "40,*###($ " fullword ascii /* hex encoded string '@' */
      $s3 = "$3D$5D$ '" fullword ascii /* hex encoded string '=]' */
      $s4 = "** HUGE PA" fullword ascii
      $s5 = "RkeyedW;" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 1000KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

