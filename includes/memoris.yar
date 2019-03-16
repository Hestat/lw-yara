/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-03-16
   Identifier: 03-16-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_03_16_19_memoris {
   meta:
      description = "03-16-19 - file memoris.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-16"
      hash1 = "23535566bbbf822d7b4afa57b527ad6b406ccb9bf69329dd5f00bbbde8c6335a"
   strings:
      $s1 = "$MessageSubject = base64_decode($_POST[\"msgsubject\"]);" fullword ascii
      $s2 = "$MessageHeader = base64_decode($_POST[\"msgheader\"]);" fullword ascii
      $s3 = "$MessageBody = base64_decode($_POST[\"msgbody\"]);" fullword ascii
      $s4 = "$MailTo = base64_decode($_POST[\"mailto\"]);" fullword ascii
      $s5 = "if(mail($MailTo,$MessageSubject,$MessageBody,$MessageHeader))" fullword ascii
      $s6 = "if(isset($_POST[\"msgheader\"]))" fullword ascii
      $s7 = "if(isset($_POST[\"msgsubject\"]))" fullword ascii
      $s8 = "if(isset($_POST[\"mailto\"]))" fullword ascii
      $s9 = "if(isset($_POST[\"msgbody\"]))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}
