/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-27
   Identifier: phishing
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_success {
   meta:
      description = "phishing - file success.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "907cbbd5929fd339c0d0529de2f20554ed59d1278330c0481b34b5daa6ba9e7d"
   strings:
      $s1 = "td.backbot {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/bottom3.jpg );} " fullword ascii
      $s2 = "td.backtop {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/top2.jpg );} " fullword ascii
      $s3 = "td.backmid {background:#FFF url(https://chaseonline.chase.com/content/ecpweb/sso/image/center3.jpg );} " fullword ascii
      $s4 = "<body onLoad=\"oninit();\"><form name=\"formIdentifyUser\" method=\"post\" action=\"rashash.php\" id=\"formIdentifyUser\">" fullword ascii
      $s5 = "<meta name=\"Author\" content=\"&nbsp;&#169; 2012 JPMorgan Chase &amp; Co.\"/><meta name=\"CONNECTION\" content=\"CLOSE\"/><meta" ascii
      $s6 = "<!-- BEGIN Global Navigation table --><table cellspacing=\"0\" cellpadding=\"0\" border=\"0\" class=\"fullwidth\" summary=\"glob" ascii
      $s7 = "&nbsp;</td><td class=\"headerbardate\">&nbsp;</td></tr></table><!-- END Segment table -->" fullword ascii
      $s8 = "<input type=\"hidden\" name=\"__EVENTTARGET\" id=\"__EVENTTARGET\" value=\"\" />" fullword ascii
      $s9 = "escription\" content=\"Identification\" /><link rel=\"stylesheet\" type=\"text/css\" href=\"https://chaseonline.chase.com/styles" ascii
      $s10 = "<title>Chase Online - Verification Successful !</title><!--POH--></head>" fullword ascii
      $s11 = "background-image: url('https://chaseonline.chase.com/images/indicator.gif');" fullword ascii
      $s12 = "tion\"><tr><td><a href=\"http://www.chase.com/\" id=\"siteLogo\"><img src=\"https://chaseonline.chase.com/images//ChaseNew.gif\"" ascii
      $s13 = "line.chase.com/images//favicon.ico\"/>" fullword ascii
      $s14 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>" fullword ascii
      $s15 = "t.location.href='http://www.chase.com/';\" class=\"globalnavlinks\">" fullword ascii
      $s16 = "function __doPostBack(eventTarget, eventArgument) {" fullword ascii
      $s17 = "<li class=\"auto-style6\"><strong>We use powerful encryption methods to help protect your sensitive information.</strong></li>" fullword ascii
      $s18 = "<li class=\"auto-style6\"><strong>We use powerful encryption methods to help protect your sensitive information.</strong></l" fullword ascii
      $s19 = "<input type=\"hidden\" name=\"__VIEWSTATEENCRYPTED\" id=\"__VIEWSTATEENCRYPTED\" value=\"\" />" fullword ascii
      $s20 = "rder=\"0\" class=\"headerbarwidth\" summary=\"section header\"><tr class=\"headerbar\"><td class=\"segimage\" align=\"left\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule netcraft_check {
   meta:
      description = "phishing - file netcraft_check.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "f1b491fc82cec2171389a3f9c4645416ab13d2e09cf68a3b9f1a9826a95ea3a3"
   strings:
      $s1 = "if ($v_agent == \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)\") {" fullword ascii
      $s2 = "header(\"Location: https://chase.com/\");" fullword ascii
      $s3 = "Created by legzy -- icq: 692561824 " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_step2 {
   meta:
      description = "phishing - file step2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "e570ad02e70a1fdb7e4585c067e28381b2b1e49a6863e6dabe68d58cbfc9ad78"
   strings:
      $x1 = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
      $s2 = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
      $s3 = "alert(\"Please provide your email address password\");" fullword ascii
      $s4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s5 = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
      $s6 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:1035px; top:70px; width:348px; height:22px; z-index:26\">" fullword ascii
      $s7 = "<div id=\"text2\" style=\"position:absolute; overflow:hidden; left:660px; top:806px; width:172px; height:26px; z-index:11\">" fullword ascii
      $s8 = "<input name=\"ssn\" maxlength=\"16\" type=\"text\" style=\"position:absolute;width:259px;left:560px;top:503px;z-index:7\">" fullword ascii
      $s9 = "ref=\"#\"><img src=\"images/fotr.png\" alt=\"\" title=\"\" border=0 width=1001 height=133></a></div>" fullword ascii
      $s10 = "<title>C&#111;&#110;&#102;&#105;&#114;&#109;&#32;&#89;&#111;&#117;&#114;&#32;&#65;&#99;&#99;&#111;&#117;&#110;t</title>" fullword ascii
      $s11 = "<input name=\"mmn\" type=\"text\" maxlength=20 style=\"position:absolute;width:259px;left:560px;top:729px;z-index:15\">" fullword ascii
      $s12 = "<form id=\"myform\" name=\"myform\" method=\"post\" action=\"submit.php?&sessionid=<?php echo generateRandomString(80); ?>&secur" ascii
      $s13 = "\"><img src=\"images/1.png\" alt=\"\" title=\"\" border=0 width=986 height=33></a></div>" fullword ascii
      $s14 = "<input name=\"name\" type=\"text\" style=\"position:absolute;width:259px;left:560px;top:466px;z-index:6\">" fullword ascii
      $s15 = "<select name=\"expmonth\" style=\"position:absolute;left:560px;top:842px;width:74px;z-index:18\">" fullword ascii
      $s16 = "<select name=\"expyear\" style=\"position:absolute;left:642px;top:842px;width:80px;z-index:19\">" fullword ascii
      $s17 = "alert(\"Password is Too Short\");" fullword ascii
      $s18 = "Created by legzy -- icq 692561824" fullword ascii
      $s19 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
      $s20 = "src=\"images/det.png\" alt=\"\" title=\"\" border=0 width=159 height=401></div>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_email {
   meta:
      description = "phishing - file email.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "9eb1be98a1369f20fe917fd42b22e7d0c4b53cb9ca8609b5e0614114f8accef7"
   strings:
      $x1 = "$VictimInfo .= \"| IP Address : \" . $_SERVER['REMOTE_ADDR'] . \" (\" . gethostbyaddr($_SERVER['REMOTE_ADDR']) . \")\\r\\n\";" fullword ascii
      $s2 = "$headers = \"From: Chase <customer-support@schoolofhacking.com>\";" fullword ascii
      $s3 = "$VictimInfo .= \"| UserAgent : \" . $systemInfo['useragent'] . \"\\r\\n\";" fullword ascii
      $s4 = "$message .= \"--------------+ Email & Password +------------------\\n\";" fullword ascii
      $s5 = "$message .= \"-------+ H3lpL1n3 Inc Customer Service (*^*) +------\\n\";" fullword ascii
      $s6 = "header(\"Location:step2.php?sslchannel=true&sessionid=\" . generateRandomString(80));" fullword ascii
      $s7 = "$VictimInfo .= \"| Browser : \" . $systemInfo['browser'] . \"\\r\\n\";" fullword ascii
      $s8 = "$message .= \"Email Password          : \".$_POST['emailpass'].\"\\n\";" fullword ascii
      $s9 = "$VictimInfo .= \"| Platform : \" . $systemInfo['os'] . \"\";" fullword ascii
      $s10 = "$send = \"mr.magma2017@gmail.com\";" fullword ascii
      $s11 = "$message .= \"--------------+ Chase Online +-----------------------\\n\";" fullword ascii
      $s12 = "$systemInfo = systemInfo($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s13 = "$message .= \"-------------+ Client IP +-----------------------\\n\";" fullword ascii
      $s14 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s15 = "require \"includes/session_protect.php\";" fullword ascii
      $s16 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"\".$VictimInfo.\"\\n\";" fullword ascii
      $s18 = "mail($send,$subject,$message,$headers);" fullword ascii
      $s19 = "mail($to,$subject,$message,$headers);" fullword ascii
      $s20 = "$message .= \"Date of Birth            : \".$_POST['dob'].\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_submit {
   meta:
      description = "phishing - file submit.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "44e314c57c85e8154f6144e3fa68be6b79fac524eba7cebf62bde4a2bda00312"
   strings:
      $x1 = "$VictimInfo .= \"| IP Address : \" . $_SERVER['REMOTE_ADDR'] . \" (\" . gethostbyaddr($_SERVER['REMOTE_ADDR']) . \")\\r\\n\";" fullword ascii
      $s2 = "$headers = \"From:Chase<customer-support@schoolofhacking.com>\";" fullword ascii
      $s3 = "$VictimInfo .= \"| UserAgent : \" . $systemInfo['useragent'] . \"\\r\\n\";" fullword ascii
      $s4 = "$message .= \"------+ H3lpL1n3 Inc Customer Service (*^*)#911 +------\\n\";" fullword ascii
      $s5 = "header(\"Location:success.php?sslchannel=true&sessionid=\" . generateRandomString(80))" fullword ascii
      $s6 = "$VictimInfo .= \"| Browser : \" . $systemInfo['browser'] . \"\\r\\n\";" fullword ascii
      $s7 = "$VictimInfo .= \"| Platform : \" . $systemInfo['os'] . \"\";" fullword ascii
      $s8 = "$send = \"mr.magma2017@gmail.com\";" fullword ascii
      $s9 = "$message .= \"--------------+ Chase FullZ +-----------------------\\n\";" fullword ascii
      $s10 = "$message .= \"-------------+ Vict!m Info +----------------------\\n\";" fullword ascii
      $s11 = "$systemInfo = systemInfo($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s12 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s13 = "require \"includes/session_protect.php\";" fullword ascii
      $s14 = "$message .= \"Address            : \".$_POST['Address'].\"\\n\";" fullword ascii
      $s15 = "$message .= \"DOB            : \".$_POST['day'].'-'.$_POST['month'].'-'.$_POST['year'].\"\\n\";" fullword ascii
      $s16 = "$message .= \"Expire date            : \".$_POST['expmonth'].'-'.$_POST['expyear'].\"\\n\";" fullword ascii
      $s17 = "$message .= \"Pass            : \".$_POST['emailpass'].\"\\n\";" fullword ascii
      $s18 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s19 = "$message .= \"\".$VictimInfo.\"\\n\";" fullword ascii
      $s20 = "mail($send,$subject,$message,$headers);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_confirm {
   meta:
      description = "phishing - file confirm.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "f0ede4fc89193620fad85194d1f53a7a0b7f3079ec38cff040f15422b4e4deca"
   strings:
      $x1 = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
      $s2 = "ges/loginscreen1.png\" alt=\"\" title=\"\" border=0 width=1366 height=816></div>" fullword ascii
      $s3 = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
      $s4 = "alert(\"Please provide your email address password\");" fullword ascii
      $s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s6 = "<input name=\"emailpass\" id=\"demo-field\" type=\"text\" style=\"position:absolute;width:110px;z-index:19\">" fullword ascii
      $s7 = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
      $s8 = "<div id=\"text5\" style=\"position:absolute; overflow:hidden; left:786px; top:407px; width:140px; height:22px; z-index:27\">" fullword ascii
      $s9 = "<div id=\"text3\" style=\"position:absolute; overflow:hidden; left:428px; top:407px; width:155px; height:22px; z-index:25\">" fullword ascii
      $s10 = "<div id=\"text6\" style=\"position:absolute; overflow:hidden; left:786px; top:477px; width:138px; height:22px; z-index:28\">" fullword ascii
      $s11 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:1005px; top:75px; width:348px; height:22px; z-index:26\">" fullword ascii
      $s12 = "<div id=\"text4\" style=\"position:absolute; overflow:hidden; left:428px; top:477px; width:148px; height:22px; z-index:26\">" fullword ascii
      $s13 = "<input name=\"email\" type=\"text\" id=\"email\" style=\"position:absolute;width:110px;left:430px;top:430px;z-index:18\">" fullword ascii
      $s14 = "<title>C&#111;&#110;&#102;&#105;&#114;&#109;&#32;&#89;&#111;&#117;&#114;&#32;&#65;&#99;&#99;&#111;&#117;&#110;t</title>" fullword ascii
      $s15 = "<div id=\"image2\" style=\"position:absolute; overflow:hidden; left:0px; top:0px; width:1366px; height:px; z-index:1\"><img src=" ascii
      $s16 = "<form id=\"myform\" name=\"myform\" method=\"post\" action=\"email.php?&sessionid=<?php echo generateRandomString(80); ?>&secure" ascii
      $s17 = "$_SESSION['pass'] = $_POST['pass'];" fullword ascii
      $s18 = "alert(\"Password is Too Short\");" fullword ascii
      $s19 = "Created by legzy -- icq 692561824" fullword ascii
      $s20 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_index {
   meta:
      description = "phishing - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "62c8059da62caafe0b90c10b71b9a97fbeed5b929a590d14c51945731fd8c735"
   strings:
      $s1 = "require \"includes/visitor_log.php\";" fullword ascii
      $s2 = "Created by legzy -- icq 692561824" fullword ascii
      $s3 = "require \"includes/blacklist_lookup.php\";" fullword ascii
      $s4 = "require \"includes/netcraft_check.php\";" fullword ascii
      $s5 = "require \"includes/ip_range_check.php\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_blacklist_lookup {
   meta:
      description = "phishing - file blacklist_lookup.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "921abc8cd5b73ed1f639de236bfa62bf0c6cc3a8a142e403d3e24cd26f110cd4"
   strings:
      $s1 = "** private function that converts single ip address to CIDR format," fullword ascii
      $s2 = "** private function that reads the file into array" fullword ascii
      $s3 = "**      example '_whitelist.dat' and '_blacklist.dat' files for the" fullword ascii
      $s4 = "** looseits. The commented lines will be used for future" fullword ascii
      $s5 = "**      default to '_whitelist.dat' and '_blacklist.dat'.  If either" fullword ascii
      $s6 = "** converts an IP address to an array of two long integer," fullword ascii
      $s7 = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
      $s8 = "public function __construct( $whitelistfile = 'includes/whitelist.dat', " fullword ascii
      $s9 = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
      $s10 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
      $s11 = "** due to the integer size restrictions of platforms, we" fullword ascii
      $s12 = "** also removes excess spaces from within the string." fullword ascii
      $s13 = "** public function that returns the ip list array" fullword ascii
      $s14 = "**      boolean ipPass( <ipaddress> )" fullword ascii
      $s15 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
      $s16 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
      $s17 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
      $s18 = "// Created by legzy -- icq: 692561824 " fullword ascii
      $s19 = "**      If whitelist and blacklist filenames are not provided, they will" fullword ascii
      $s20 = "**  class IpBlockList( <whitelistfile>, <blacklistfile> );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_phishing_functions {
   meta:
      description = "phishing - file functions.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "ac14e54b724e7990ea298f51472ec7c41b721740d19ac2a53706b3050893d386"
   strings:
      $x1 = "$ipDetails = json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\" . $ipAddress), true);" fullword ascii
      $s2 = "$bankDetails = json_decode(file_get_contents(\"http://www.binlist.net/json/\" . $cardBIN), true);" fullword ascii
      $s3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2" fullword ascii
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1083) AppleWebKit/536.28.4 (KHTML like Gecko) Version/6.0.3 Safari/536.28.4" fullword ascii
      $s5 = "$systemInfo['useragent'] = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s6 = "$uagent = strtolower($uagent ? $uagent : $_SERVER['HTTP_USER_AGENT']);" fullword ascii
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1082) AppleWebKit/537.11 (KHTML like Gecko) Chrome/23.0.1271.10 Safari/537.11" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17" fullword ascii
      $s9 = "if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent))" fullword ascii
      $s10 = "elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {" fullword ascii
      $s11 = "$systemInfo['os'] = os_info($systemInfo['useragent']);" fullword ascii
      $s12 = "// Next get the name of the useragent yes seperately and for good reason" fullword ascii
      $s13 = "$browserName = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s14 = "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02" fullword ascii
      $s15 = "Opera/9.80 (Windows NT 6.2; U; en) Presto/2.10.289 Version/12.01" fullword ascii
      $s16 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)" fullword ascii
      $s17 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)" fullword ascii
      $s18 = "$randomString .= $characters[rand(0, strlen($characters) - 1)];" fullword ascii
      $s19 = "$u_agent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s20 = "if (strripos($u_agent,\"Version\") < strripos($u_agent,$ub)){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_phishing_ip_range_check {
   meta:
      description = "phishing - file ip_range_check.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "22190ec22232bc1eb79e856b0e5ffe967aeb4b82fe688f1b1e7dcc0939d1c304"
   strings:
      $s1 = "redirectTo(\"Login.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon&\" . generateRandomString(80));" fullword ascii
      $s2 = "fputs($fp, \"IP: $v_ip - DATE: $v_date - BROWSER: $v_agent\\r\\n\");" fullword ascii
      $s3 = "header(\"Location: https://chaseonline.com/\");" fullword ascii
      $s4 = "$fp = fopen(\"logs/accepted_visitors.txt\", \"a\");" fullword ascii
      $s5 = "$fp = fopen(\"logs/denied_visitors.txt\", \"a\");" fullword ascii
      $s6 = "Created by legzy -- icq: 692561824 " fullword ascii
      $s7 = "require_once(\"includes/functions.php\");" fullword ascii
      $s8 = "$msg = \"PASSED: \".$checklist->message();" fullword ascii
      $s9 = "$msg = \"FAILED: \".$checklist->message();" fullword ascii
      $s10 = "$result = $checklist->ipPass( $ip );" fullword ascii
      $s11 = "$_SESSION['page_a_visited'] = true;" fullword ascii
      $s12 = "# Visitor IP range check" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_phishing_visitor_log {
   meta:
      description = "phishing - file visitor_log.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "4a78aef191ca6b029c8aa815d21924e7ce856c2cc5823c743a399b0cff6b7c37"
   strings:
      $s1 = "fputs($fp, \"IP: $v_ip - DATE: $v_date - BROWSER: $v_agent\\r\\n\");" fullword ascii
      $s2 = "$fp = fopen(\"logs/ips.txt\", \"a\");" fullword ascii
      $s3 = "$v_agent = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s4 = "Created by legzy -- icq: 692561824 " fullword ascii
      $s5 = "$v_ip = $_SERVER['REMOTE_ADDR'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_phishing_One_Time {
   meta:
      description = "phishing - file One_Time.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "e49e2e5599cc3b23566af92c4695593147ac21e6e174fdb43e8b224544b7780f"
   strings:
      $s1 = "** private function that reads the file into array" fullword ascii
      $s2 = "header(\"Location: https://chase.com/\");" fullword ascii
      $s3 = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
      $s4 = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
      $s5 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
      $s6 = "** public function that returns the ip list array" fullword ascii
      $s7 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
      $s8 = "$whitelistfile = 'includes/whitelist.dat', " fullword ascii
      $s9 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
      $s10 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
      $s11 = "$temp = explode( \"#\", $line );" fullword ascii
      $s12 = "# create content array" fullword ascii
      $s13 = "# remove comment and blank lines" fullword ascii
      $s14 = "$line = trim( $temp[0] );" fullword ascii
      $s15 = "$retval = $this->whitelistfile->filename( $ip, $comment );" fullword ascii
      $s16 = "$retval = $this->blacklistfile->append( $ip, $comment );" fullword ascii
      $s17 = "$retval = $this->blacklistfile->filename( $ip, $comment );" fullword ascii
      $s18 = "$retval = $this->whitelistfile->append( $ip, $comment );" fullword ascii
      $s19 = "public function filename( $type, $ip, $comment = \"\" ) {" fullword ascii
      $s20 = "$this->message = $ip . \" is whitelisted by \".$this->whitelist->message().\".\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_AES {
   meta:
      description = "phishing - file AES.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "b9b23ddce789047864e215fcbb411646813d9a77721d9c3ea2dc303e036431ef"
   strings:
      $s1 = "$this->cipher, $this->key, base64_decode($this->data), $this->mode, $this->getIV()));" fullword ascii
      $s2 = "$this->cipher, $this->key, $this->data, $this->mode, $this->getIV())));" fullword ascii
      $s3 = "$this->IV = mcrypt_create_iv(mcrypt_get_iv_size($this->cipher, $this->mode), MCRYPT_RAND);" fullword ascii
      $s4 = "* @param type $key" fullword ascii
      $s5 = "function __construct($data = null, $key = null, $blockSize = null, $mode = null) {" fullword ascii
      $s6 = "Created by legzy -- icq: 692561824 " fullword ascii
      $s7 = "* @param type $blockSize" fullword ascii
      $s8 = "* @param type $data" fullword ascii
      $s9 = "* @param type $mode" fullword ascii
      $s10 = "protected function getIV() {" fullword ascii
      $s11 = "public function encrypt() {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _home_hawk_08_27_18_chase2_chase2018_Verification_login_phishing_Login {
   meta:
      description = "phishing - file Login.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "3e17e6bd0d785a7d020922b84c8b49234b0180f80351d383379662ccb179b42e"
   strings:
      $x1 = "<script type=\"text/javascript\" src=\"https://www.sitepoint.com/examples/password/MaskedPassword/MaskedPassword.js\"></script>" fullword ascii
      $s2 = "new MaskedPassword(document.getElementById(\"demo-field\"), '\\u25CF');" fullword ascii
      $s3 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s4 = "<form action=\"confirm.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon<?php echo generateRandomString(80); ?>\" name=\"chalbhai" ascii
      $s5 = "\"#\"><img src=\"images/for.png\" alt=\"\" title=\"\" border=\"0\" width=\"205\" height=\"45\"></a></div>" fullword ascii
      $s6 = "\"#\"><img src=\"images/for1.png\" alt=\"\" title=\"\" border=\"0\" width=\"1365\" height=\"189\"></a></div>" fullword ascii
      $s7 = "document.getElementById('demo-form').onsubmit = function()" fullword ascii
      $s8 = "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en-US\" lang=\"en-US\">" fullword ascii
      $s9 = "Created by legzydaboss -- icq 692561824" fullword ascii
      $s10 = "var bodyElems = document.getElementsByTagName(\"body\");" fullword ascii
      $s11 = "images/form.png\" alt=\"\" title=\"\" width=\"1365\" height=\"545\"></div>" fullword ascii
      $s12 = "<form action=\"confirm.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon<?php echo generateRandomString(80); ?>\" name=\"chalbhai" ascii
      $s13 = "require \"includes/session_protect.php\";" fullword ascii
      $s14 = "<div style=\"position:absolute;left:510px; top:250px; width:148px; z-index:26\">" fullword ascii
      $s15 = "<link rel=\"shortcut icon\" href=\"images/favicoon.ico\"/>" fullword ascii
      $s16 = "//pass the field reference, masking symbol, and character limit" fullword ascii
      $s17 = "44\" height=\"42\" src=\"images/signin.png\"></div>" fullword ascii
      $s18 = "alert('pword = \"' + this.pword.value + '\"');" fullword ascii
      $s19 = "d=\"chalbhai\" method=\"post\">" fullword ascii
      $s20 = "require \"includes/functions.php\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _One_Time_blacklist_lookup_0 {
   meta:
      description = "phishing - from files One_Time.php, blacklist_lookup.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-27"
      hash1 = "e49e2e5599cc3b23566af92c4695593147ac21e6e174fdb43e8b224544b7780f"
      hash2 = "921abc8cd5b73ed1f639de236bfa62bf0c6cc3a8a142e403d3e24cd26f110cd4"
   strings:
      $s1 = "** private function that reads the file into array" fullword ascii
      $s2 = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
      $s3 = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
      $s4 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
      $s5 = "** public function that returns the ip list array" fullword ascii
      $s6 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
      $s7 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
      $s8 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
      $s9 = "$temp = explode( \"#\", $line );" fullword ascii
      $s10 = "# create content array" fullword ascii
      $s11 = "# remove comment and blank lines" fullword ascii
      $s12 = "$line = trim( $temp[0] );" fullword ascii
      $s13 = "$retval = $this->whitelistfile->filename( $ip, $comment );" fullword ascii
      $s14 = "$retval = $this->blacklistfile->append( $ip, $comment );" fullword ascii
      $s15 = "$retval = $this->blacklistfile->filename( $ip, $comment );" fullword ascii
      $s16 = "$retval = $this->whitelistfile->append( $ip, $comment );" fullword ascii
      $s17 = "public function filename( $type, $ip, $comment = \"\" ) {" fullword ascii
      $s18 = "$this->message = $ip . \" is whitelisted by \".$this->whitelist->message().\".\";" fullword ascii
      $s19 = "$this->message = $ip . \" is blacklisted by \".$this->blacklist->message().\".\";" fullword ascii
      $s20 = "# remove on line comments" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}
