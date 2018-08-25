/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-25
   Identifier: redirect
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_25_18_redirect_index {
   meta:
      description = "redirect - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "3eb001a420107db7c78640d8d1f7c8984e19f39f4f03b09dbf7f42c79f19ae45"
   strings:
      $s1 = "<?php ${\"G\\x4c\\x4f\\x42ALS\"}[\"f\\x65\\x78\\x67\\x74\\x69\\x72\\x76\\x64\\x66\"]=\"\\x73r\\x63\";${\"\\x47\\x4c\\x4f\\x42\\x" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( all of them )
      ) or ( all of them )
}


rule infected_08_25_18_blackhole_2 {
   meta:
      description = "redirect - file blackhole.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "a883fd80964028ce8578bcf99de10274ef0e7f6bfc02eafd787e963e00d645fe"
   strings:
      $s1 = "if(realpath(__FILE__)===realpath($_SERVER[" fullword ascii
      $s2 = "x77\\x78fp\\x73i\\x71\"]})){header(\"L\\x6f\\x63at\\x69on:\\x20/\",true,302);exit;}${${\"\\x47\\x4cOB\\x41\\x4c\\x53\"}[\"by\\x6" ascii
      $s3 = "<?php ${\"\\x47L\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x75\\x63\\x65z\\x6b\\x62\\x6e\\x77\\x65i\\x67\"]=\"s\\x74r\\x69n\\x67\";${\"GL" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( all of them )
      ) or ( all of them )
}


rule infected_08_25_18_redirect_bienvenue_index {
   meta:
      description = "redirect - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "8cba56fbd792e090accc0f9489bc5900d9396382b2fd506c01efa178e9ce18c8"
   strings:
      $s1 = "<?php ${\"\\x47L\\x4fBAL\\x53\"}[\"\\x73\\x70fthl\\x6ary\"]=\"me\\x73s\\x61\\x67e\";${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x" ascii
      $s2 = "x\\x6fv\\x75\\x69v\"]}=\"w\\x68\\x6fi\\x73\\x2e\\x61r\\x69n\\x2e\\x6eet\";$fopock=\"\\x69pa\\x64\\x64\\x72\\x65\\x73\\x73\";if(!" ascii
      $s3 = "${\"G\\x4c\\x4f\\x42AL\\x53\"}[\"\\x70qdl\\x61i\\x6dmsjm\"]}.\"\\x20- \".${${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x66f\\x6e" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( all of them )
      ) or ( all of them )
}

