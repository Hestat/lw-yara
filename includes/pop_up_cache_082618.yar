/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-26
   Identifier: 08-26-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule pop_up_cache_obsfuscated_malware {
   meta:
      description = "08-26-18 - file pop-up-cache.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-26"
      hash1 = "cd3f2a4a97098fd34619efaf298b68c3b2ff356f5fba071f4fef91ceb752d5de"
   strings:
      $s1 = "$zzrrzrz___=base64_decode(\"bjF6Ym1hNXZ0MGkyOC1weHVxeTZscmtkZzlfZWhjc3dvNGYzN2o=\");$z__zr_zzrr=$zzrrzrz___{30}.$zzrrzrz___{8}.$" ascii
      $s2 = "zrr__zr);}}');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x7a\\x72\\x5f\\x7a\\x5f\\x7a\\x72\\x5f\\x7a\\x72\"]();?>" fullword ascii
      $s3 = "x7a\\x5f\\x5f\\x7a\\x72\"])?80:$zrrz_z__rz[\"\\x7a\\x5f\\x72\\x7a\\x72\\x7a\\x5f\\x5f\\x7a\\x72\"];}$zrr_zz_rz_=\\'Host:\\';$zrr" ascii
      $s4 = "__zzrrrz_,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x7a\\x5f\\x72\\x5f\\x5f\\x72\\x72\\x7a\\x7" ascii
      $s5 = "sdLtPS1wIA\\');unset($zrr_zz_rz_);$zrrzzz___r=\"GET $z__z_zzrrr HTTP/$z__rzr_rzz\\\\r\\\\n\".${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 60KB and
         ( all of them )
      ) or ( all of them )
}

