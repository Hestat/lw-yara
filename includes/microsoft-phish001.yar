/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-11
   Identifier: microsoft-phish
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule quotaview_incoming_microsoft_phish_next2 {
   meta:
      description = "microsoft-phish - file next2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "1b17ccf2f6deaff79993028ddf843cc90367445d61a8f1d2acdeebe7fb38e4b8"
   strings:
      $s1 = "$message .= \"-----------  ! +Xoom LOGIN ! xDD+ !  -----------\\n\";" fullword ascii
      $s2 = "$headers = \"From: Herren <herren.ruth@gmail.com>\";" fullword ascii
      $s3 = "$message .= \"-----------  ! +Account infoS+ !  -----------\\n\";" fullword ascii
      $s4 = "$message .= \"Password : \".$_POST['pass'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"-----------  ! +nJoY+ !  -----------\\n\";" fullword ascii
      $s6 = "$message .= \"Email : \".$_POST['userid'].\"\\n\";" fullword ascii
      //$s7 = "$send = \"herren.ruth@gmail.com\";" fullword ascii
      $s8 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s9 = "header(\"Location: complete.php\");" fullword ascii
      $s10 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s11 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s12 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s13 = "$message .= \"IP Address : \".$ip.\"\\n\";" fullword ascii
      $s14 = "$message .= \"CVV : \".$_POST['card_code'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule hostname_quotaview_incoming_microsoft_phish {
   meta:
      description = "microsoft-phish - file hostname.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "b81fb37dc48812f6ad61984ecf2a8dbbfe581120257cb4becad5375a12e755bb"
   strings:
      $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']); //Get User Hostname" fullword ascii
      $s2 = "* hostname.php" fullword ascii
      $s3 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s4 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s5 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule quotaview_incoming_microsoft_phish_index {
   meta:
      description = "microsoft-phish - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "bec638fbc9edfbd8e65ee9dec04b921d12eb51a7cfd2862c348b4780b729b500"
   strings:
      $s1 = "header(\"location: login.php?cmd=login_submit&id=$praga$praga&session=$praga$praga\");" fullword ascii
      $s2 = "require_once 'hostname.php';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}



/* Super Rules ------------------------------------------------------------- */

