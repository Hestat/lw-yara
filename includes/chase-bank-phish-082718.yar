/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-27
   Identifier: chase
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_27_18_chase_bank_phish_access {
   meta:
      description = "chase - file access.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "2bfe60be990c045955c439f2e22b8aa0fe2393ea79b82a38abf38cd5fcf04c62"
   strings:
      $s1 = "header(\"Location:  https://chaseonline.chase.com/Logon.aspx?LOB=RBGLogon\");" fullword ascii
      $s2 = "$recipient =" fullword ascii
      $s3 = "$message .= \"Email Password              : \".$_POST['emailpassx'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"Email Address             : \".$_POST['emailxnx'].\"\\n\";" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$message .= \"---- : || tHAnks tO Phish || :------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase_bank_phish_verify {
   meta:
      description = "chase - file verify.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "8c9a2a71e438b74d92a0454c69097e952c23c5d5fc78899f965256852d6c71ef"
   strings:
      $s1 = "$recipient =" fullword ascii
      $s2 = "$message .= \"Password              : \".$_POST['Password'].\"\\n\";" fullword ascii
      $s4 = "header(\"Location:  log.htm\");" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$message .= \"---- : || tHAnks tO PHish || :------\\n\";" fullword ascii
      $s7 = "$message .= \"User ID             : \".$_POST['UserID'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

