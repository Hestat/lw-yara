/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-02-22
   Identifier: 02-22-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_02_22_19_yt9 {
   meta:
      description = "02-22-19 - file yt9.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-02-22"
      hash1 = "aef6a4ec5ff827c7c64d58d0a2e69e97dc4f068674ed9d491405125690953f5e"
   strings:
      $s1 = "6b\"]($l1wb,\"GET $l1yg5ril HTTP/1.0\\r\\nHost:\".$l1QnNwu1[\"host\"].\"\\r\\nConnection:Close\\r\\n\\r\\n\");$l1ZWYO='';while(!" ascii
      $s2 = "';$bb6bb=explode(\"1l\",\"esolc_lruc1lfoef1lstsixe_noitcnuf1lteg_ini1ldro1ltroba_resu_erongi1lstegf1ldomhc1ltilps_gerp1lemitotrt" ascii
      $s4 = "CURLOPT_URL,$l1fwC);$GLOBALS[\"b6bb66b6\"]($l1BoXNr,CURLOPT_USERAGENT,$GLOBALS[\"bb66b66\"]);$GLOBALS[\"b6bb66b6\"]($l1BoXNr,CUR" ascii
      $s5 = "\"host\"],isset($l1QnNwu1[\"port\"])?$l1QnNwu1[\"port\"]:80,$l1j26ya,$l13Q,30);if($l1wb){$l1yg5ril=isset($l1QnNwu1[\"path\"])?$l" ascii
      $s6 = "b6b6666\"].$_SERVER[\"HTTP_HOST\"].$_SERVER[\"REQUEST_URI\"];l1urD5xY($l15halO);}function l1urD5xY($l1fwC){$l1yg5ril=0;if($GLOBA" ascii
      $s7 = "Y[\"HTTP_X_FORWARDED_SSL\"]){return true;}if($GLOBALS[\"bb6bbb66b\"]($GLOBALS[\"b6bb6\"],$l1TXY)&&$GLOBALS[\"b6666\"]===$l1TXY[" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 2 of them )
      ) or ( all of them )
}


rule infected_02_22_19_fljm {
   meta:
      description = "02-22-19 - file fljm.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-02-22"
      hash1 = "1c27a38537e44aea98db227207d904eefb868d0a82034b53be7b76f535371dc6"
   strings:
      $s1 = "str_replace(\"j\",\"\",\"sjtrj_jrjejpljajcje\")" ascii
      $s2 = "<?php"
      $s3 = "(\"i\", \"\", \"ibiaisie6i4i_dieicoide\");"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 2 of them )
      ) or ( all of them )
}

