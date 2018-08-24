/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: WP index injection
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule possible_injected_wordpress_settings {
   meta:
      description = "Wordpress injection wp-settings.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
   strings:
      $s1 = "@include" fullword ascii
      $s2 = ".\\x69c\\x6f" ascii
      $s3 = "@package WordPress" fullword ascii
      $s4 = "require( ABSPATH . WPINC . '/post.php' );"
   condition:
         ( all of them )
}
