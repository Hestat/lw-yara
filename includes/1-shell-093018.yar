/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: shell
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_shell_1 {
   meta:
      description = "shell - file 1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "f6ada75e14c1aa942ea8c2ca556f05a063ff49f077ee096540e87d7621a68310"
   strings:
      $s1 = "if(@!eregi('.php',$b) && @!eregi('.txt',$b) && @!eregi('.html',$b) && @!eregi('htaccess',$b) && @!eregi('.ftp',$b))" fullword ascii
      $s2 = "$html=@file_get_contents($file);" fullword ascii
      $s3 = "$html2=@file_get_contents('456789123');" fullword ascii
      $s4 = "$pass='$1$c5WCj0vT$pW/B8Jo3SKkcDsD1WrJtP0:16249::::::';" fullword ascii
      $s5 = "$html1=@str_replace(array(\"\\n\",\"\\r\", \"\\r\\n\" ,\" \"), \"\", $html);" fullword ascii
      $s6 = "if($_GET['mw']=='delete'){" fullword ascii
      $s7 = "@fwrite($save,\"$abc:$pass\\r\\n\");" fullword ascii
      $s8 = "$pat=array(\"\",'../','../../','../../../','../../../../','../../../../../','../../../../../../');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( all of them )
      ) or ( all of them )
}

