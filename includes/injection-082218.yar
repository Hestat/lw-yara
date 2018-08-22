/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-22
   Identifier: shell3
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_082218_class_wp_widget_rss {
   meta:
      description = "shell3 - file class-wp-widget-rss.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "346a6eb57f54748497993779617c35b4971a8c11a0f5a9c95c274568b480bfa7"
   strings:
      $s1 = "s66ab'][13]]($kc3cfc0f)==3){eval/*teb79*/($kc3cfc0f[1]($kc3cfc0f[2]));exit();}}} ?><?php" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( all of them )
      ) or ( all of them )
}

