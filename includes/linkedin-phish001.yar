/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-17
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_17_18_linkedin_phishing_connect {
   meta:
      description = "phishing - file connect.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-17"
      hash1 = "42488aee3cec937049e5313438a033fd89993bba7627d55a40abdeed289e8ba6"
   strings:
      $s1 = "$country = file_get_contents('http://api.hostip.info/country.php?ip='.$IP);" fullword ascii
      $s2 = "header(\"Location: http://www.linkedin.com/pub/dir/Import/Export\");" fullword ascii
      $s3 = "$message .= \"-------------- LoginZ By By CYCLOPZ-----------------------\\n\";" fullword ascii
      $s4 = "$message .= \"Verify-Password: \".$_POST['paasv'].\"\\n\";" fullword ascii
      $s5 = "$message .= \"Password: \".$_POST['pass'].\"\\n\";" fullword ascii
      $s6 = "$headers = \"From:MESSAGE Mp Boss<CYCLOPZ@CYCLOPZ.COM>\";" fullword ascii
      $s7 = "$message .= \"Linkedin !ID: \".$_POST['session_key'].\"\\n\";" fullword ascii
      $s8 = "$log_date = date('d/m/Y - h:i:s');" fullword ascii
      //$s9 = "$recipient = \"serverupdate@yahoo.com,spaul8608@gmail.com\";" fullword ascii
      $s10 = "mail(\"$to\", \"Linkedin Login\", $message);" fullword ascii
      $s11 = "$subject = \"Linkedin LOGIN\";" fullword ascii
      $s12 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s13 = "if (mail($recipient,$subject,$message,$headers))" fullword ascii
      $s14 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s15 = "$message .= \"---------------Created By By bobychenko------------------------------\\n\";" fullword ascii
      $s16 = "$message .= \"Date : \".$log_date.\"\\n\";" fullword ascii
      $s17 = "$headers .= $_POST['name'].\"\\n\";" fullword ascii
      $s18 = "echo \"ERROR! Please go back and try again.\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_17_18_linkedin_phishing_login {
   meta:
      description = "phishing - file login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-17"
      hash1 = "dbc399649c8a1f6127fb866d99a87c71c0a589d343d6294408e9953e55efe5df"
   strings:
      $x1 = "<a href=\"https://help.linkedin.com/app/answers/detail/a_id/34593/loc/na/trk/uas-consumer-login-internal/\" target=\"_blank\" re" ascii
      $x2 = "<a href=\"https://help.linkedin.com/app/answers/detail/a_id/34593/loc/na/trk/uas-consumer-login-internal/\" target=\"_blank\" re" ascii
      $x3 = "=global_kb',influencerUrl:'http:\\/\\/www.linkedin.com\\/influencers?trk=global_kb'});</script>" fullword ascii
      $x4 = "<a href=\"https://www.linkedin.com/uas/login?goback=&amp;trk=hb_signin\" class=\"nav-link\" rel=\"nofollow\">" fullword ascii
      $s5 = "<link rel=\"shortcut icon\" href=\"https://static.licdn.com/scds/common/u/images/logos/favicons/v1/favicon.ico\">" fullword ascii
      $s6 = "<link rel=\"shortcut icon\" href=\"https://static.licdn.com/scds/common/u/images/logos/favicons/v1/16x16/favicon.ico\">" fullword ascii
      $s7 = "tion(){YAHOO.util.Get.script(\"https://ssl.google-analytics.com/ga.js\");});</script>" fullword ascii
      $s8 = "<link rel=\"icon\" href=\"https://static.licdn.com/scds/common/u/images/logos/favicons/v1/favicon.ico\">" fullword ascii
      $s9 = "seUrl=\"https://static.licdn.com/scds/concat/common/css?v=build-2000_8_39110-prod\";LI.staticUrlHashEnabled=true;</script>" fullword ascii
      $s10 = "<script type=\"text/javascript\">var _gaq=_gaq||[];_gaq.push(['_setAccount','UA-3242811-1']);_gaq.push(['_setDomainName','.linke" ascii
      $s11 = "<input type=\"text\" name=\"session_key\"  id=\"session_key-login\" value=\"<?php $action = $_REQUEST[\"userid\"]; " fullword ascii
      $s12 = "<meta name=\"lnkd-track-lib\" content=\"https://static.licdn.com/scds/concat/common/js?h=ebbt2vixcc5qz0otts5io08xv\">" fullword ascii
      $s13 = "<link rel=\"apple-touch-icon-precomposed\" href=\"https://static.licdn.com/scds/common/u/img/icon/apple-touch-icon.png\">" fullword ascii
      $s14 = "(function(){var bcookie=escape(LI.readCookie(\"bcookie\")),newTrkInfo='null',alias_secure='/analytics/noauthtracker?type=leo%2Ep" ascii
      $s15 = "<script id=\"control-http-12274-exec-13264179-2\" type=\"linkedin/control\" class=\"li-control\">LI.KbDialogDependencies={jsFile" ascii
      $s16 = "<meta name=\"globalTrackingUrl\" content=\"http://www.linkedin.com/mob/tracking\">" fullword ascii
      $s17 = "<li><a href=\"http://www.linkedin.com/legal/user-agreement?trk=hb_ft_userag\">User Agreement</a></li>" fullword ascii
      $s18 = "<li><a href=\"http://www.linkedin.com/legal/cookie-policy?trk=hb_ft_cookie\">Cookie Policy</a></li>" fullword ascii
      $s19 = "<link rel=\"canonical\" href=\"https://www.linkedin.com/uas/login\"/>" fullword ascii
      $s20 = "v1*v2*v3)%1000000007;}return{compute:compute,computeJson:computeJson,version:\"1.0.1\"};}());</script>" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 70KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
