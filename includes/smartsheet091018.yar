/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-12
   Identifier: account
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */


rule infected_09_10_18_phishing_smartsheet_data {
   meta:
      description = "account - file data.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-12"
      hash1 = "dee2198836643c8f440533264b416e648d51badc106824cc770cb431e3f26b0b"
   strings:
      $s1 = "$message .= \"Password: \".$_POST['passwd'].\"\\n\";" fullword ascii
      $s2 = "$message .= \"Username: \".$_POST['login'].\"\\n\";" fullword ascii
      $s3 = "\"User-Agent: \".$browser.\"\\n\";" fullword ascii
      $s4 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s5 = "$recipient = \"johnwashington1960@gmail.com\";" fullword ascii
      $s6 = "} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { " fullword ascii
      $s7 = "//get user's ip address " fullword ascii
      $s8 = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR']; " fullword ascii
      $s9 = "$hostname = gethostbyaddr($ip);" fullword ascii
      $s10 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s11 = "if (mail($recipient,$subject,$message,$headers))" fullword ascii
      $s12 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s13 = "$message .= \"HostName : \".$hostname.\"\\n\";" fullword ascii
      $s14 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s15 = "header(\"Location: index3.php\");" fullword ascii
      $s16 = "$headers = \"From: OFFBox\";" fullword ascii
      $s17 = "if (!empty($_SERVER['HTTP_CLIENT_IP'])) { " fullword ascii
      $s18 = "$ip = $_SERVER['HTTP_CLIENT_IP']; " fullword ascii
      $s19 = "\"Country Code: {$geoplugin->countryCode}\\n\";" fullword ascii
      $s20 = "$message .= \"======================================\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_09_10_18_phishing_smartsheet_index3 {
   meta:
      description = "account - file index3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-12"
      hash1 = "58479bd9dd37fb60a285ce31e5a2917181a59b4c76cd8ab689da25cefd64cb85"
   strings:
      $x1 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0" fullword ascii
      $s2 = "<meta http-equiv=\"refresh\" content=\"5;url=https://onedrive.live.com/\" />" fullword ascii
      $s3 = "TenantBranding.AddBoilerPlateText(Constants.DEFAULT_BOILERPLATE_TEXT, Constants.DEFAULT_BOILERPLATE_HEADER);" fullword ascii
      $s4 = "<img src=\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/microsoft_logo.png\" id=\"IMG_12\" alt=''" ascii
      $s5 = "User.UpdateLogo(Constants.DEFAULT_LOGO, Constants.DEFAULT_LOGO_ALT);" fullword ascii
      $s6 = "Constants.DEFAULT_ILLUSTRATION = 'https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/default_signin_ill" ascii
      $s7 = "Constants.DEFAULT_ILLUSTRATION = 'https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/default_signin_ill" ascii
      $s8 = "User.UpdateBackground(Constants.DEFAULT_ILLUSTRATION, Constants.DEFAULT_BACKGROUND_COLOR);" fullword ascii
      $s9 = "User.UpdateLogo('', \"You signed out of your account\", true);" fullword ascii
      $s10 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0-sm" ascii
      $s11 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0.jp" ascii
      $s12 = "Constants.DEFAULT_LOGO_ALT = 'Hang on a moment while we sign you out.';" fullword ascii
      $s13 = "document.cookie = \"SOS\" + \"=1; path=/\";" fullword ascii
      $s14 = "signoutStatusMessage.text(\"You may still be signed in to some applications. Close your browser to finish signing out.\");" fullword ascii
      $s15 = "<script type=\"text/javascript\" id=\"SCRIPT_2\">function SetImageStatus(imageIndex, status)" fullword ascii
      $s16 = "<script type=\"text/javascript\" id=\"SCRIPT_18\">$Do.when(\"doc.ready\", function ()" fullword ascii
      $s17 = "<script type=\"text/javascript\" id=\"SCRIPT_3\">var imageStatusArray = new Array(0);" fullword ascii
      $s18 = "Constants.DEFAULT_BOILERPLATE_HEADER = '';" fullword ascii
      $s19 = "signoutStatusMessage.text(\"It\\u0027s a good idea to close all browser windows.\");" fullword ascii
      $s20 = "Constants.BOILERPLATE_HEADER = '';" fullword ascii
   condition:
      ( uint16(0) == 0x733c and
         filesize < 60KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule infected_09_10_18_phishing_smartsheet_htaccess {
   meta:
      description = "account - file .htaccess"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-12"
      hash1 = "797d267648e4045ac790950c234fc6f33d8c20ae51f8c4d6be1a233ab3684c05"
   strings:
      $s1 = "deny from blogger.com" fullword ascii
      $s2 = "deny from blogs.eset-la.com" fullword ascii
      $s3 = "deny from infospyware.com" fullword ascii
      $s4 = "deny from opera.com" fullword ascii
      $s5 = "deny from fireeye.com" fullword ascii
      $s6 = "Deny from morgue1.corp.yahoo.com" fullword ascii
      $s7 = "Deny from crawl8-public.alexa.com" fullword ascii
      $s8 = "deny from wilderssecurity.com" fullword ascii
      $s9 = "Deny from tracerlock.com" fullword ascii
      $s10 = "deny from malwaredomainlist.com" fullword ascii
      $s11 = "Deny from pixnat09.whizbang.com" fullword ascii
      $s12 = "deny from community.norton.com" fullword ascii
      $s13 = "deny from welivesecurity.com" fullword ascii
      $s14 = "deny from virustotal.com" fullword ascii
      $s15 = "deny from alienvault.com" fullword ascii
      $s16 = "deny from minotauranalysis.com" fullword ascii
      $s17 = "Deny from pixnat06.whizbang.com" fullword ascii
      $s18 = "Deny from hanta.yahoo.com" fullword ascii
      $s19 = "deny from gdatasoftware.com" fullword ascii
      $s20 = "Deny from zeus.nj.nec.com" fullword ascii
   condition:
      ( uint16(0) == 0x6564 and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

