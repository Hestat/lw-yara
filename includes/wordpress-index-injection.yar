/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: WP index injection
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule possible_injected_wordpress_index {
   meta:
      description = "shell2 - file eg.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
   strings:
      $s1 = "@include" fullword ascii
      $s2 = ".\\x69c\\x6f" ascii
      $s3 = "@package WordPress" fullword ascii
      $s4 = "define('WP_USE_THEMES', true)"
   condition:
         ( all of them )
}

