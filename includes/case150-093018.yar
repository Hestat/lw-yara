/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_wp_load {
   meta:
      description = "shell2 - file wp-load.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "4095f37c624a3d93600dd974343fa016c4b16090c07cf39c523382ec34956dc9"
   strings:
      $s1 = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
      $s2 = "$data = file_get_contents($url);" fullword ascii
      $s3 = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
      $s4 = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
      $s5 = "$pass = \"Zgc5c4MXrLUscwQO6MwbPPGCf1TVMvlanyHMAanN\";" fullword ascii
      $s6 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
      $s7 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
      $s8 = "function get_data_ya($url) {" fullword ascii
      $s9 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s10 = "@ini_set('display_errors', '0');" fullword ascii
      $s11 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_30_18_cache_clear {
   meta:
      description = "shell2 - file cache.clear.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "4b4a78553e8c9f03c0713bed9059d828bb8d7512b3404482993df4cfa4d28d13"
   strings:
      $s1 = "<?php $MZz9092 = \"tr7_zj13lp)f4hd0ny;8suwqi529.mk6/o*avebx(cg\";$AI2908 = $MZz9092[9].$MZz9092[1].$MZz9092[37].$MZz9092[42].$MZ" ascii
      $s2 = "zzsW/EH6uL3xjfBfPQlftp+p89WMv+6Yv6O3J38v/ae4fybwPeeXkYlhf+/K87ycD5C//gI+OIFneb4lfFH+/0t9VeG/G+tzYH2Tvwf+92j9Xfze1FeTD/Ig/CH9Hzv3" ascii
      $s3 = "C72/D3k+ntBfiZeE/5/wKfJz+X6xz3l+4sOmP7Fmpjo/R/GfhKeQP9zZD1HzbNW3qdcup0X/dzU/Ef+Hd38G9fcF80/Ndx7Jj2yK9P23fgx/VvsFTPBv8C+hf63HxV/Z" ascii
      $s4 = "GLXvx9TfOH9e81z0a/g3m58gf2z8LZ1/zD6Un0Bl3Q/4zAv8m5i/nOGXB/+//H/ly6X/fkkdKX4a/FB6pRZ/JK2v9Id3PvU18yPt/yN9/sr6NdVjk3EW+/PH/dllfx/6" ascii
      $s5 = "5fl98meNj6n+lP7A+Ve1+6VH/BHIs9jjryN/F9ff0bcW5Fdea+cq4meyeJijF0b/IH9Uz190/l7Ql0ufUJ3Qd5NTkXn19I+t9Q3KH7V+0v4F66x/g+e9Gp0POpifuOiv" ascii
      $s6 = "5y/8t+APXfFndX1k/pD1NfDrj/AirC9f53rW/TzY0xd+gOZnqoepd1UHwmGGn1mgv+X5nuFXRL0QNa39h9DvDNR/HfNoeH3C7/ExEX56WvwR8V87gHeW8FtUZ4hfOdnn" ascii
      $s7 = "+W+zyvzBifnejhxE8B/hquCvzqfTPV2jzxHuVHOe/If8zxL+BhmUnP8xX5e+r0S/LP3PFj7PVfP7Af5CBX879WPX9/lS5/zZbkz/bvOrNE9YWR9nf7vMBxf/s3QdKf6e" ascii
      $s8 = "576jPpc+wfWg8tmPC3+F/q1f6jvlP6uv2/Ne28UfCT5CnI/xPXee15i/B15mfzdy6+GPp7/5ivf77m9pv2bPGslXGbhfwn8o7h/8xXVuznc6uqkS/Fz4Cvh9J/2H9T/C" ascii
      $s9 = "SP/SF/vTMP8wDx3930h+b/K75edlf07ze5d80Zp8pszHHFfov1TfZn62/UGv5GO7/+rND+LzjS38KvTR7lsr51On/uj+xj7LmX94dj6N/eejPnmkXhAfXfNn+g/zv52P" ascii
      $s10 = "Z978yv6R3hV+GvlLB/z7OvON0h+lQJ+99Pf+/OvMb7P+Zf3hPf+KfIOj9U/2R7b/TMP8wJ4j+J+N7o/vdubnhu4/87Vq9Mua3z3ij6acw9J+XzX4gu7/ltpUGAv+VJXr" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( all of them )
      ) or ( all of them )
}

