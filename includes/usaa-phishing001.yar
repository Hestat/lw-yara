/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-16
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_08_16_18_usaa_page_phishing_first {
   meta:
      description = "phishing - file first.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "681caec18a82b9dfe60b5fccb94604ec06620ae72537792a7a3d81faa86f3a4b"
   strings:
      $s1 = "$message .= \"--------------Usaa Login Info-----------------------\\n\";" fullword ascii
      $s2 = "$message .= \"Login ID            : \".$_POST['formtext1'].\"\\n\";" fullword ascii
      $s3 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s4 = "$message .= \"Password             : \".$_POST['formtext2'].\"\\n\";" fullword ascii
      $s5 = "$headers = \"From: Usaa result<customer-support@mrs>\";" fullword ascii
      $s6 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s7 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s8 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s9 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s10 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s11 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
      $s12 = "$subject = \"Result from -$ip\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_16_18_usaa_page_phishing_mailer {
   meta:
      description = "phishing - file mailer.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "4fb064375415e844bed994aebe1caf09b9a646f20d4daceefb4f4f4262af007c"
   strings:
      //$s1 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s2 = "$headers = \"From: usaa result<customer-support@mrs>\";" fullword ascii
      $s3 = "$message .= \"Email Address             : \".$_POST['formtext3'].\"\\n\";" fullword ascii
      $s4 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s7 = "$message .= \"Confirm PIN Number           : \".$_POST['formtext12'].\"\\n\";" fullword ascii
      $s8 = "$message .= \"Date of Birth             : \".$_POST['formtext8'].\"\\n\";" fullword ascii
      $s9 = "$message .= \"USAA Member Number            : \".$_POST['formtext2'].\"\\n\";" fullword ascii
      $s10 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s11 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s12 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
      $s13 = "$subject = \"Result from -$ip\";" fullword ascii
      $s14 = "$message .= \"Phone Pin           : \".$_POST['formtext13'].\"\\n\";" fullword ascii
      $s15 = "$message .= \"Full Name             : \".$_POST['formtext1'].\"\\n\";" fullword ascii
      $s16 = "$message .= \"SSN 1             : \".$_POST['formtext5'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"Expiry Date          : \".$_POST['formtext10'].\"\\n\";" fullword ascii
      $s18 = "$message .= \"SSN 3             : \".$_POST['formtext7'].\"\\n\";" fullword ascii
      $s19 = "$message .= \"SSN 2             : \".$_POST['formtext6'].\"\\n\";" fullword ascii
      $s20 = "$message .= \"--------------Skype Info-----------------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_16_18_usaa_page_phishing_second {
   meta:
      description = "phishing - file second.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "fcbd6b43f0447982d3195483d69a03c9c8095cd0e1b7ecd33784cd21e81a8b33"
   strings:
      //$s1 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s2 = "$headers = \"From: Usaa result<customer-support@mrs>\";" fullword ascii
      $s3 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s4 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s5 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s6 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s7 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s8 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
      $s9 = "$subject = \"Result from -$ip\";" fullword ascii
      $s10 = "$message .= \"Pin            : \".$_POST['formtext103'].\"\\n\";" fullword ascii
      $s11 = "$message .= \"--------------Usaa Pin Info-----------------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_16_18_usaa_page_phishing_action {
   meta:
      description = "phishing - file action.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-16"
      hash1 = "44e246c90089c88c7583c11d5e410176480b9e2f89b882ee45a831602ce3eca8"
   strings:
      $s1 = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
      $s2 = "$headers = \"From: USAA result<customer-support@mrs>\";" fullword ascii
      $s3 = "$message .= \"Question 1 : \".$_POST['formselect1'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"Answer  1 : \".$_POST['formtext1'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"Answer 3 : \".$_POST['formtext3'].\"\\n\";" fullword ascii
      $s6 = "$message .= \"Question 2 : \".$_POST['formselect2'].\"\\n\";" fullword ascii
      $s7 = "$message .= \"Answer 2 : \".$_POST['formtext2'].\"\\n\";" fullword ascii
      $s8 = "$message .= \"Question 3  : \".$_POST['formselect3'].\"\\n\";" fullword ascii
      $s9 = "$message .= \"Question 4 : \".$_POST['formselect4'].\"\\n\";" fullword ascii
      $s10 = "$message .= \"Answer 4 : \".$_POST['formtext4'].\"\\n\";" fullword ascii
      $s11 = "$message .= \"Question 5 : \".$_POST['formselect5'].\"\\n\";" fullword ascii
      $s12 = "$message .= \"Question 6 : \".$_POST['formselect6'].\"\\n\";" fullword ascii
      $s13 = "$message .= \"Answer 5 : \".$_POST['formtext5'].\"\\n\";" fullword ascii
      $s14 = "$message .= \"Answer 6 : \".$_POST['formtext6'].\"\\n\";" fullword ascii
      $s15 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s16 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s17 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s18 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s19 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s20 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 8 of them )
      ) or ( all of them )
}
