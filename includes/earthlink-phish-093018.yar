/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: phish
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_09_30_18_earthlink_phish_index {
   meta:
      description = "phish - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "fb94a67c38e4564efc164df7608959de76c8c47428db9515fb434957a8a3ce05"
   strings:
      $s1 = "$message .= \"Pass.::::::::::::::: \".$_POST['password'].\"\\n\";" fullword ascii
      $s2 = "header(\"Location: login.htm\");" fullword ascii
      $s3 = "$message .= \"--------------Earthlink Smtp Rezultat-----------------------\\n\";" fullword ascii
      $s4 = "$recipient =\"aheithaway@gmail.com\";" fullword ascii
      $s5 = "$message .= \"Email.::::::::::::: \".$_POST['email'].\"\\n\";" fullword ascii
      $s6 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s7 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s8 = "$subject = \"Earthlink Smtp ReZulT\";" fullword ascii
      $s9 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s10 = "echo \"ERROR! Please go back and try again.\";" fullword ascii
      $s11 = "{$carca = mail($recipient,$subject,$message,$headers);}" fullword ascii
      $s12 = "$message .= \"---------------Re-Modified By nONE-------\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_30_18_earthlink_phish_login {
   meta:
      description = "phish - file login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "bdd407f674a537da7b4cd20d883be4ef8d2ec7052261256f8775d69dd0de4749"
   strings:
      $s1 = "$message .= \"Address1.::::::::::::: \".$_POST['address1'].\"\\n\";" fullword ascii
      $s2 = "$message .= \"Emailpass.::::::::::::: \".$_POST['emailpass'].\"\\n\";" fullword ascii
      $s3 = "$message .= \"address2.::::::::::::: \".$_POST['address2'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"Email.::::::::::::: \".$_POST['emailaddress'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"--------------Earthlink Smtp Rezultat-----------------------\\n\";" fullword ascii
      $s6 = "$recipient =\"aheithaway@gmail.com\";" fullword ascii
      $s7 = "$message .= \"mobilenumber.::::::::::::: \".$_POST['mobilenumber'].\"\\n\";" fullword ascii
      $s8 = "$message .= \"homephone.::::::::::::: \".$_POST['homephone'].\"\\n\";" fullword ascii
      $s9 = "$message .= \"Birthdate.::::::::::::: \".$_POST['birthdate'].\"\\n\";" fullword ascii
      $s10 = "$message .= \"ccnumber.::::::::::::::: \".$_POST['ccnumber'].\"\\n\";" fullword ascii
      $s11 = "$message .= \"Expmonth.::::::::::::: \".$_POST['expmonth'].\"\\n\";" fullword ascii
      $s12 = "$message .= \"zipcode.::::::::::::: \".$_POST['zipcode'].\"\\n\";" fullword ascii
      $s13 = "$message .= \"country.::::::::::::: \".$_POST['country'].\"\\n\";" fullword ascii
      $s14 = "$message .= \"Birthyear.::::::::::::: \".$_POST['birthyear'].\"\\n\";" fullword ascii
      $s15 = "$message .= \"Birthmonth.::::::::::::: \".$_POST['birthmonth'].\"\\n\";" fullword ascii
      $s16 = "$message .= \"Fullname.::::::::::::: \".$_POST['fullname'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"Expyear.::::::::::::: \".$_POST['expyear'].\"\\n\";" fullword ascii
      $s18 = "header(\"Location: http://www.earthlink.net\");" fullword ascii
      $s19 = "$message .= \"Cctype3.::::::::::::: \".$_POST['dcc'].\"\\n\";" fullword ascii
      $s20 = "$message .= \"CVV.::::::::::::: \".$_POST['csv'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}
