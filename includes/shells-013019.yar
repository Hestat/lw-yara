/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-31
   Identifier: 01-31-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_31_19_minify {
   meta:
      description = "01-31-19 - file minify.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-31"
      hash1 = "48dee7233033b71174a063d1241754aa493ac33cd6f47487d130ed2a117f3856"
   strings:
      $s1 = "function mc($OQ,$Ba)" fullword ascii
      $s2 = "$AP=\"f152ff3d0236535f1a5feb9272731e47\";" fullword ascii
      $s3 = "<?php"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_01_31_19_mod_Php {
   meta:
      description = "01-31-19 - file mod_Php.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-31"
      hash1 = "85f6dcc537fc211d7aeef8640a6b5feb5dc226ea41350156424722e2f4fdd27c"
   strings:
      $s1 = "$VLfhEzqV1187 = \"HjwxOhEpUAxvZk9QECoHZRcpAQNVdn5NORQ2PypcUBZUAnFEECoTOCkDL1RUeWpRAzoPZBI5UBB6cmpcADobPBc5EVVuAm5NADt4PBIDL1F6cm" ascii
      $s2 = "CEy4mOxI5XFV9YmpRDyh4ACUoGgtVdXVZAj4qMz8HKAxmWHEAHjwuMzotKAJ/cnlQEy4AMzotKAJ/cnlQEy4AMzopPw9XdgBQEwQDIikHKA5Vdn5ZADUMPTwZWS5/cnl" ascii
      $s3 = "HOQd1bD9dOw1vXEBbCgQiGjAJAi96WFsPFl4TPyMEHhNSeXEcCiUTLSMEEVVsdQwPFl4TPyMEEVVsdQwPOzp0Ixc2OAJSeVRAADlwLhc5IxFXaWlQPgAHJxc5PFx/Www" ascii
      $s4 = "QA18XJxEmKw1sdmpHOAAibTkUIAt/dnZbOCo5LhApLw9XZg1ZCj4iIzkUXV1SeXEcHjwubBcpOE5geVRAADk2IhcpOE5meWpcCgYpIhBdOF16AmpcCgc5ZCkqXChUA1x" ascii
      $s5 = "9GTwqHhI5MAp/YmoHOzUTJyk9Ai9TRgh8GTwqHjA/Ai91YFRbA18pIjotCl1SeXEcEBcyGjAJAi91YFN9GTwqHikDUBxsZn5dOy4mPxI2OwlUYnpfORQAPxJcP1B/dQg" ascii
      $s6 = "ZCiUTLSMEEVVsdQwPFl4TPyMEEVVsdQwPPioHPREpPAJVAmoCOCoUbToAKw1sdmpHOAAiIBEpPwhSdVdPFDUDYDoEXV1SeXEcCiUTPyMEER9Vdn5CCgY5IilcBRBmcgF" ascii
      $s7 = "HOAc2IhcpOE5meWpcCgEDPBBdJ1ZUAnJcCi54ZCkqXV1SdmkcCCoHZCo5Iw1VA20PFl4TPyMEEVVsdQwPFl4TPyMEHhNSeXEcCiUTLSMJWS5mdlRCOSUXZDomO1BVdm0" ascii
      $s8 = "YEF14ADomMwlVX3ZHOF91Oj8tKyRsXFREADt4Oik2OwNvAwFCPioXIRcmJAp8SAFAOQB4Pj9dMwlVX3ZHOF91Ojg9AlJyYFdQEy4AMzotKAJ/cnlQEy4DZxBcUDFsZnZ" ascii
      $s9 = "HCjs2PSkXDgtkXFREADUPARFcUBZVSFtEOAMXJxEtEVVXdlRNFgAYIRcDLxZSZm1EEF9wJikDBRZsYltHFV4LOBcmPxxUWHpaAzo5Lik6HQZ/WwwPOV4DPBEEXCtvZkx" ascii
      $s10 = "$j = $P(\"/*eiGjcUfV9764*/\", $dTOsVUZI5225( mPmit($dTOsVUZI5225($VLfhEzqV1187), \"ZmATsnie6187\")));" fullword ascii
      $s11 = "cDygpBTopBRBsXAAPFl8mLCMEEQ5XaWFQA185PBBdJFxvAwFCPioXIRcqXV1VAmoCOCoUfz8AKAJTA3ZBOCp4LTwHJBJ7dXkAPDk2IhBdO1BUdm0cEBcyGjAJAi9UA3J" ascii
      $s12 = "AHjwuMzotKAJSXH5OEyoQMyM9Kw5UA3YGODoXIRcqGit1VlRaPjp0PhcpBRNUWHpNADUQOyo9EQ96eXlPFiUALT8mKB96dnZYAzULLik2OBV/eUt5GQoqHhI5MApvYn0" ascii
      $s13 = "cFjoPIhEpUBx5WHVNFxcPbTc/GRJVXG4AAAB4IRctWAhvZglHOCUqYiJcUFRVXFRbOQQ5GhFcXBNVAnpfA18UYxU/WS5mcgFNPiUtJyk6XSt1W0BNA14LJBAmOE5yYFd" ascii
      $s14 = "ZFz4iMypcPxZUeXZAAzoPJBEDClx8S3lZEyUlJCkmOwpmYlsGFy4UOiMJWS51YFN9CiUTLSMEEVVscnoEOzoTZBIqWQt7Ym1ZCgETOBYmOFNmcgEHACl1bBcpOE5mdlR" ascii
      $s15 = "aOzo5OCstIFJsdgFdPjpwOBEAOBBVA2FCOSkIIRcDLxZSZm0OPiopJBAXXAh6X2JfOCUXODxcOxNvAm5DADp0ZD8AJwh6X3YGAwBwJBctDhV5AnJbPiUXLREHKwhvZkB" ascii
      $s16 = "aOF90ZDopJxNUdgFOCjULOCkqXDViW09BAAB4IRcqXQt5WFsPAAB4IRctKw9UA0BBOQdwOhADPwlUWwwPAwd0BCEFMF16A3EcCi54ORFcXFVmWFtHHjwuMzotKAJ/cnl" ascii
      $s17 = "9ECUTIBAtKFx/dn5OOQAHYTgtDRBvZglbEBQAbSMHKA5sdlROC194IRcpPxBSd0tcOztxJzc/Bi91YFN9GT4AOhApL1VXcltQCjl1MzkrDShiAXJ1DisPNjlcJ1Zsclx" ascii
      $s18 = "QCioEMxImIwlsWwheExQIMxFcXA9UdlRdOxdxPSkXAQZ8AWJHOCoXLiUpUBNUeXZUEBQ5IRc5ERZ6d09ZEBR0ZRADEQlUXHZBACoUOzkpMwd8Aw1fODoUOis9AhB8AE9" ascii
      $s19 = "BEy4ibCkDUBxUYnpBOAMPZSoDWBVSdQheABQpIRc5ERZ6dg0GOCo2JystCgt/cgxQPjULJyk5XA9UA2pbES4TMiYrUDFgd0tZOSkEOis9AgJ6WHlZAi4iJxEAPxZUckB" ascii
      $s20 = "bOzoYOyIpBR9uA2pHOQQmPyFeETVnWn56D1wyOipdDQ58AAhQFgQAPykpBRxnAwFCPioXIRcoGg5XZwhHETxxHzA/Ai98dmpHOQMPNis9KFx/dn5OOQAHYStcWAlVXFx" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 8 of them )
      ) or ( all of them )
}
