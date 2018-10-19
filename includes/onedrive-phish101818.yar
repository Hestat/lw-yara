/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-18
   Identifier: emailcode
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_18_18_onedrive_emailcode {
   meta:
      description = "emailcode - file email.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-18"
      hash1 = "3ca994b4976f7928e3032da13d73159fdb1e8eccd1438b52f522050f3938ffa7"
   strings:
      $x1 = "header('Location: https://login.microsoftonline.com/common/oauth2');" fullword ascii
      $s2 = "$subject = \"Office login attempt -- \".$ip;" fullword ascii
      $s3 = "$subject = \"Outlook login attempt -- \".$ip;" fullword ascii
      $s4 = "$subject = \"other login attempt -- \".$ip;" fullword ascii
      $s5 = "$subject = \"Webmail login attempt -- \".$ip;" fullword ascii
      $s6 = "$message .= \"Login Type Selection -- Outlook \\n\";" fullword ascii
      $s7 = "$message .= \"Login Type Selection -- Webmail \\n\";" fullword ascii
      $s8 = "$message .= \"Login Type Selection -- Office \\n\";" fullword ascii
      $s9 = "$message .= \"Login Type Selection -- other \\n\";" fullword ascii
      $s10 = "$ip_data = str_replace('&quot;', '\"', $ip_data); // for PHP 5.2 see stackoverflow.com/questions/3110487/" fullword ascii
      $s11 = "$message .= \"Password -- $password\\n\";" fullword ascii
      $s12 = "$headers .= 'Content-type: text/html; charset=iso-8859-1' . \"\\r\\n\"; " fullword ascii
      $s13 = "// To send HTML mail, the Content-type header must be set" fullword ascii
      $s14 = "$headers .= \"Content-Type: text/html; charset=ISO-8859-1\\r\\n\";" fullword ascii
      $s15 = "$message .= \"Username/Email -- $email\\n\";" fullword ascii
      $s16 = "$admin_email" fullword ascii
      $s17 = "$formname = $_REQUEST['logintype'];" fullword ascii
      $s18 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s19 = "curl_setopt($ch, CURLOPT_URL, \"http://www.geoplugin.net/json.gp?ip=\".$ip);" fullword ascii
      $s20 = "$message .= \"Region Detected --  \".$region.\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
