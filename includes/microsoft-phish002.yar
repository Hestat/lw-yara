/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-17
   Identifier: script
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_17_18_microsoft_phishing {
   meta:
      description = "script - file throwit.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-17"
      hash1 = "58aa21f585268e84641601ad644f22de57b363c813005efbd63fe29f58cc3ac6"
   strings:
      $s1 = "header(\"Location: http://login.microsoftonline.com\");" fullword ascii
      $s2 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      $s3 = "$message .= \"PASS 2: \".$_POST['password2'].\"\\n\";" fullword ascii
      $s4 = "$message .= \"PASS 1: \".$_POST['password'].\"\\n\";" fullword ascii
      $s5 = "$headers .= \"Content-type:text/html;charset=UTF-8\" . \"\\r\\n\";" fullword ascii
      $s6 = "$sent" fullword ascii
      $s7 = "$message .= \"EMAIL: \".$_POST['username'].\"\\n\";" fullword ascii
      $s8 = "$handle = fopen(\"script.txt\", \"a\");" fullword ascii
      $s9 = "$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      $s10 = "$headers = \"MIME-Version: 1.0\" . \"\\r\\n\";" fullword ascii
      $s11 = "$array = array(114,101,115,117,108,116,98,111,120,49,52,64,103,109,97,105,108,46,99,111,109);" fullword ascii
      $s12 = "$subject = \"REMITTANCE - \";" fullword ascii
      $s13 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s14 = "$headers = \"From: SCRIPT>\";" fullword ascii
      $s15 = "elseif(filter_var($forward, FILTER_VALIDATE_IP))" fullword ascii
      $s16 = "$message .= \"---------=IP Address & Date=---------\\n\";" fullword ascii
      $s17 = "// Function to get country and country sort;" fullword ascii
      $s18 = "mail($mesaegs,$subject,$message,$headers);" fullword ascii
      $s19 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
      $s20 = "mail($sent,$subject,$message,$headers);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 8 of them )
      ) or ( all of them )
}
