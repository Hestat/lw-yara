rule infected_05_26_18_updw {
   meta:
      description = "05-26-18 - file updw.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "ed154c632a07aae4b65eb20e5c903c0a6e21e4f9eddc254885ef4b4a57564812"
   strings:
      $s1 = "$url3=\"http://www.datacen2017.top/drupal/request-sanitizer.txt\";" fullword ascii
      $s2 = "$url4=\"http://www.datacen2017.top/drupal/update-core.txt\";" fullword ascii
      $s3 = "$url1=\"http://www.datacen2017.top/drupal/del.txt\";" fullword ascii
      $s4 = "$url2=\"http://www.datacen2017.top/drupal/dr.txt\";" fullword ascii
      $s5 = "file_put_contents(\"./request-sanitizer.inc\", $str_hm3);" fullword ascii
      $s6 = "file_put_contents(\"./update-core.php\", $str_hm4);" fullword ascii
      $s7 = "file_put_contents(\"./del.php\", $str_hm1);" fullword ascii
      $s8 = "file_put_contents(\"./dr.php\", $str_hm2);" fullword ascii
      $s9 = "echo \"download is fail\";" fullword ascii
      $s10 = "if($filesize1 == '104'&& $filesize2 == '3202'&& $filesize3 == '2990'&& $filesize4 == '2275'){" fullword ascii
      $s11 = "curl_setopt($curl, CURLOPT_HEADER, false);" fullword ascii
      $s12 = "$data=curl_exec($curl);" fullword ascii
      $s13 = "$filesize4=abs(filesize(\"./update-core.php\"));" fullword ascii
      $s14 = "echo \"download is sucesss.\";" fullword ascii
      $s15 = "$filesize3=abs(filesize(\"./request-sanitizer.inc\"));" fullword ascii
      $s16 = "$str_hm1 = curl_get($url1);" fullword ascii
      $s17 = "$str_hm2 = curl_get($url2);" fullword ascii
      $s18 = "$str_hm3 = curl_get($url3);" fullword ascii
      $s19 = "$str_hm4 = curl_get($url4);" fullword ascii
      $s20 = "$filesize1=abs(filesize(\"./del.php\"));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 8 of them )
      ) or ( all of them )
}
