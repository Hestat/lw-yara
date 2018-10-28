/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: 10-29-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://blog.sucuri.net/2018/10/saskmade-net-redirects.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_29_18_saskmade_net {
   meta:
      description = "10-29-18 - redirect code"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "4b6b3b2353ec7e6799ec439aeb8d09c4208e81876d7c7f8a07df6360f14452b9"
   strings:
      $s1 = "var _0x1e35=['length','fromCharCode','createElement','type','async','code121','src','appendChild','getElementsByTagName','script" ascii
      $s2 = "var _0x1e35=['length','fromCharCode','createElement','type','async','code121','src','appendChild','getElementsByTagName','script" ascii
      $s3 = "{if(scrpts[i]['id']==_0x5a05('0x4')){n=![];}};if(n==!![]){a();}" fullword ascii
   condition:
      ( uint16(0) == 0x6176 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
