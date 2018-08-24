/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_24_18_upload_shell_ubh {
   meta:
      description = "shell1 - file ubh.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
      hash1 = "4634c53823dad3fdef4ee22fddf30d077f1613fc077918bb4b45cad5105d546a"
   strings:
      $s1 = "Description: upload shell and manage site or server using console :D, happy hacking ;) !" fullword ascii
      $s2 = "add_action" fullword ascii
      $s3 = "function(){add_object_page"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

