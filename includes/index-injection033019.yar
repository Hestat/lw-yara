/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-03-30
   Identifier: 03-30-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_03_30_19_index_injection {
   meta:
      description = "03-30-19 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-30"
      hash1 = "b77081e5e47352abc53201528bede29991279353807673742f75a8406eeb7a3b"
   strings:
      $x1 = "';$bbb6b6b66=explode(\"1l\",\"tilps_gerp1ledocnelru1lemaner1lyarra_ni1lezilairesnu1lstegf1l5dm1lcexe_lruc1lofniphp1lstnetnoc_teg" ascii
      $s2 = "3459234735" ascii /* hex encoded string '4Y#G5' */
      $s3 = "3639556352" ascii /* hex encoded string '69UcR' */
      $s4 = "3639555328" ascii /* hex encoded string '69US(' */
      $s5 = "2850357247" ascii /* hex encoded string '(P5rG' */
      $s6 = "3639556963" ascii /* hex encoded string '69Uic' */
      $s7 = "3639553535" ascii /* hex encoded string '69U55' */
      $s8 = "3459234728" ascii /* hex encoded string '4Y#G(' */
      $s9 = "3626237951" ascii /* hex encoded string '6&#yQ' */
      $s10 = "3639553536" ascii /* hex encoded string '69U56' */
      $s11 = "3344430079" ascii /* hex encoded string '3DCy' */
      $s12 = "3639556864" ascii /* hex encoded string '69Uhd' */
      $s13 = "3639552355" ascii /* hex encoded string '69U#U' */
      $s14 = "3639552352" ascii /* hex encoded string '69U#R' */
      $s15 = "3639555840" ascii /* hex encoded string '69UX@' */
      $s16 = "3522775360" ascii /* hex encoded string '5"wS`' */
      $s17 = "3522775367" ascii /* hex encoded string '5"wSg' */
      $s18 = "3639555071" ascii /* hex encoded string '69UPq' */
      $s19 = "x3c!DOCTYPE html>\\n\\x3chtml>\\n\\x3chead>\\n\\t\\x3cmeta charset=\\\"utf-8\\\">\\n\\t\\x3cmeta http-equiv=\\\"X-UA-Compatible" ascii
      $s20 = "1.0\\r\\nHost:\".$l14yYfXH[\"host\"].\"\\r\\nConnection:Close\\r\\n\\r\\n\");$l1lTyog='';while(!$GLOBALS[\"bbb6b6\"]($l14a)){$l1" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and 2 of them )
      ) or ( all of them )
}
