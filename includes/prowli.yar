/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-07
   Identifier: prowli
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_06_07_18_prowli_botnet_IOC3_C2 {
   meta:
      description = "prowli - file IOC3-C2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-07"
      hash1 = "4b5066f743ec9fb32c85c579b12b87a10b9433a9988ce4439b07f82a553bfb6f"
   strings:
      $s1 = "ip2_log.txt" fullword ascii
      $s2 = "ip3_log.txt" fullword ascii
      $s3 = "mhcl_log.txt" fullword ascii
      $s4 = "dru_log.txt" fullword ascii
      $s5 = "ip4_log.txt" fullword ascii
      $s6 = "$myfile = file_put_contents( " fullword ascii
      $s7 = "elseif ( isset ($_GET[" fullword ascii
      $s8 = "if ( isset ($_GET[" fullword ascii
      $s9 = "if ( isset ($_GET[ " fullword ascii
   condition:
      ( uint16(0) == 0x6669 and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule _infected_06_07_18_prowli_botnet_IOC2 {
   meta:
      description = "prowli - file IOC2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-07"
      hash1 = "39dbf136e4191edaae8bb30aa0085ebd7e998d3b89cfb623a5a7e49f573c71ea"
   strings:
      $s1 = "99, 117, 109, 101, 110, 116, 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 122, 41, 59));" fullword ascii
      //$s2= "<script language=javascript>eval(String.fromCharCode(118, 97, 114, 32, 122, 32, 61,"
   condition:
      ( uint16(0) == 0x733c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule _infected_06_07_18_prowli_botnet_IOC1 {
   meta:
      description = "prowli - file IOC1.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-07"
      hash1 = "0050aeefafcf679f9b9a925341d4ed61a9eb5c3e3fc17b653af730d543b6b080"
   strings:
      $s1 = "104, 116, 116, 112, 115, 58, 47, 47, 115, 116, 97, 116, 115, 46, 115, 116, 97, 114, 116, 114, 101, 99, 101, 105, 118, 101, 46, " fullword ascii
      $s2 = ", 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 122, 41, 59));" fullword ascii
      $s3 = "eval(String.fromCharCode" fullword ascii
   condition:
      ( uint16(0) == 0x7665 and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

