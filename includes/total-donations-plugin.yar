/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-27
   Identifier: 01-27-19
   Reference: https://github.com/Hestat/lw-yara/
   Reference: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6703
   Reference: https://www.wordfence.com/blog/2019/01/wordpress-sites-compromised-via-zero-day-vulnerabilities-in-total-donations-plugin/
*/

/* Rule Set ----------------------------------------------------------------- */

rule the_ajax_caller {
   meta:
      description = "01-27-19 - file the-ajax-caller.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-27"
      hash1 = "7574d791231f41ab64d3934efccc52e1e0396b63f7e3e3c046ba4e3ca0c1beda"
   strings:
      $s1 = "$action = esc_attr(trim($_POST['action']));" fullword ascii
      $s2 = "if(is_user_logged_in())" fullword ascii
      $s3 = "//For logged in users" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
