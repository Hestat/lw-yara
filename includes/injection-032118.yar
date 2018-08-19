/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-19
   Identifier: shellcode
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule injection {
   meta:
      description = "shellcode - file injection.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-19"
      hash1 = "ea0616654ea7e38500fe3da07e38944dba174ec61bef3411fa6d4739c36a98de"
   strings:
      $s1 = "$ydrw = $sdyf('', $gstl($lodj(\"u\", \"\", $aguj.$syem.$rdby.$acrw))); $ydrw(); ?>" fullword ascii
      $s2 = "$acrw=\"RfZGVjubu2RlKCRufUuE9TVFsnudXBukYXRlJ10puKTt9\";" fullword ascii
      $s3 = "$sdyf = $lodj(\"p\",\"\",\"pcprepaptpe_pfupnpctpipopn\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
