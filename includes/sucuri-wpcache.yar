/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-10
   Identifier: 11-10-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://blog.sucuri.net/2018/11/erealitatea-net-hack-corrupts-websites-with-wp-gdpr-compliance-plugin-vulnerability.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_11_10_18_wp_cache {
   meta:
      description = "11-10-18 - file wp-cache.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-11-10"
      hash1 = "0cb269e10c1c0e315f07f3d7536472056f4b830a48dc739d02ff30454a1f5780"
   strings:
      $s1 = "Array('str_' .'rot13','pack','st' .'rrev'" fullword ascii
      $s2 = "php function _1178619035" fullword ascii
      $s3 = "return isset($_COOKIE" fullword ascii
      $s4 = "$GLOBALS['_79565595_']" fullword ascii  
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 2 of them )
      ) or ( all of them )
}
