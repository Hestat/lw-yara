/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-02
   Identifier: 10-02-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_02_18_xmlrpc {
   meta:
      description = "10-02-18 - file xmlrpc.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-02"
      hash1 = "cff439c34b4cf5428157d104d356c88633c8d92e6c8d1d6dd7bd46eca21ddc63"
   strings:
      $s1 = "$file = file_get_contents('http://132.232.67.18:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . \"" ascii
      $s2 = "$file = file_get_contents('http://119.27.172.144:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . " ascii
      $s3 = "$key= $_SERVER[\"HTTP_USER_AGENT\"].$_SERVER[\"HTTP_REFERER\"];" fullword ascii
      $s4 = "$file = file_get_contents('http://119.27.172.144:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . " ascii
      $s5 = "$file = file_get_contents('http://132.232.67.18:8000/'.\"/index.php?host=\".$host_name.\"&url=\" . $_SERVER['QUERY_STRING'] . \"" ascii
      $s6 = "$key= $_SERVER[\"HTTP_USER_AGENT\"];" fullword ascii
      $s7 = "os($key,'Easou')!==false||strpos($key,'360')!==false||strpos($key,'haosou')!==false||strpos($key,'Soso')!==false)" fullword ascii
      $s8 = "header('Content-Type:text/html;charset=gb2312');" fullword ascii
      $s9 = "$host_name = \"http://\".$_SERVER['SERVER_NAME'].$_SERVER['PHP_SELF'];" fullword ascii
      $s10 = "$file = file_get_contents(base64_decode(\"aHR0cDovL2pzY2IuanNjMTgueHl6OjgwMDAv\").base64_decode(\"L2luZGV4LnBocD9ob3N0PQ==\").$h" ascii
      $s11 = "$file = file_get_contents(base64_decode(\"aHR0cDovL2pzY2IuanNjMTgueHl6OjgwMDAv\").base64_decode(\"L2luZGV4LnBocD9ob3N0PQ==\").$h" ascii
      $s12 = "st_name.\"&url=\" . $_SERVER['QUERY_STRING'] . \"&domain=\" . $_SERVER['SERVER_NAME']); " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

