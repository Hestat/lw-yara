/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-10
   Identifier: case140
   Reference: https://github.com/Hestat/lw-yara
*/

rule Inv_09854 {
   meta:
      description = "case140 - file Inv_09854.exe"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-10"
      hash1 = "a237b382a9fa69673a24754f5a74e292382fe2537bbacf488ec6a4e74516ab8d"
   strings:
      $x1 = "Ix93n/nfavyP+UD6cdpOXwoX3bnyA+Jk0T8yLvM1tJmyWD5T/gsPjOVBbWAckvMSE1hMhds+YRtTce21BDxQXLDyDNc1d0vJs3GA/8hY888BkL9ec4K/THF8XCryh9xO" wide
      $s2 = "XQAAgAAA1gIAAAAAAAAmlo5wABf37AW76vT/lAEvRO985vUJGUQCKf9TzdbRFP6eYZyCFfYJeqxrtO1UEJ4mynHPxUcryOsiRf5B+rNZj3IECYBvOmxexVQF3KgnEQpc" wide
      $s3 = "yBluOHC0EfcDrjAjFrkOhTax0pePFHfIOw5VwfqmE0ph3wGiM+ETnZ2VTFmmN1Ea5J727h0DoFFpSMm7N7+dfHCRtKxmyG5bSsqUqEtbk9PWWJ4pQMcb3H4nygcAc/L6" wide
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s5 = "HostExecutionContextManager" fullword ascii
      $s6 = "D8LzLfMGF1PlSOJsXLvhT7ZCalfajwoKkGF75Gauly/OHCX5CMF0EVySKBIbdfLeS+OThiy5F8oB6NBoeBfAO61Xd2W6PDXfdAuqZpER8/GHj1T28WJ/uShn1y/cMRh5" wide
      $s7 = "System.ComponentModel.Design.Serialization" fullword ascii
      $s8 = "System.ComponentModel.Design" fullword ascii
      $s9 = "http://www.wosign.com/policy/0" fullword ascii
      $s10 = "ExecuteWriteCopy" fullword ascii
      $s11 = "ExecuteReadWrite" fullword ascii
      $s12 = "System.Security.Authentication.ExtendedProtection.Configuration" fullword ascii
      $s13 = "ExecuteRead" fullword ascii
      $s14 = "TV.exe" fullword wide
      $s15 = "ExecutionContext" fullword ascii
      $s16 = "$http://crls1.wosign.com/ca1g2-ts.crl0m" fullword ascii
      $s17 = "#http://aia1.wosign.com/ca1g2.ts.cer0" fullword ascii
      $s18 = "System.Runtime.Hosting" fullword ascii
      $s19 = "http://ocsp1.wosign.com/ca1g2/ts0/" fullword ascii
      $s20 = "System.Runtime.Remoting.Services" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
         filesize < 2000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

