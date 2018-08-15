/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-14
   Identifier: admin
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */



rule paypal_phishing_admin_general {
   meta:
      description = "admin - file general.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "73897614ef03665e7929e28409dc176e38cd29dda1f7c4c0c5718823b4624d1e"
   strings:
      $s1 = "<input type=\"password\" name=\"apikey\" <?php if($xconfig == true){ echo \"value=\\\"$config_apikey\\\"\"; } ?> required>" fullword ascii
      $s2 = "@eval(file_get_contents($api->dir_config . '/' . $api->general_config));" fullword ascii
      $s3 = "<input type=\"text\" name=\"email\" <?php if($xconfig == true){ echo \"value=\\\"$email_result\\\"\"; } ?> required>" fullword ascii
      $s4 = "<div class=\"left\">Identity Photo<span>allow victim to upload their identity.</span></div>" fullword ascii
      $s5 = "<?php if($xconfig == true && $config_smtp == 1){" fullword ascii
      $s6 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s7 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s8 = "echo '<option value=\"1\" selected>smtp</option>" fullword ascii
      $s9 = "$a = $_POST['apikey'];" fullword ascii
      $s10 = "if (file_exists($api->dir_config . '/' . $api->general_config))" fullword ascii
      $s11 = "<?php if($xconfig == true && $config_translate == 1){" fullword ascii
      $s12 = "<?php if($xconfig == true && $config_filter == 1){" fullword ascii
      $s13 = "<?php if($xconfig == true && $config_3dsecure == 1){" fullword ascii
      $s14 = "<?php if($xconfig == true && $config_identity == 1){" fullword ascii
      $s15 = "<?php if($xconfig == true && $config_blocker == 1){" fullword ascii
      $s16 = "echo '<option value=\"1\">smtp</option>" fullword ascii
      $s17 = "$b = $_POST['3dsecure'];" fullword ascii
      $s18 = "$f = $_POST['translate'];" fullword ascii
      $s19 = "$photo = $_POST['identity'];" fullword ascii
      $s20 = "if (isset($_GET['success']))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule paypal_phishing_admin_smtp {
   meta:
      description = "admin - file smtp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "3c5d695e3cb12293577e118e2f84df13538945e47c219275afec10e2764161e7"
   strings:
      $s1 = "<input type=\"text\" name=\"smtphost\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtphost\\\"\"; } ?> required>" fullword ascii
      $s2 = "<input type=\"text\" name=\"smtpuser\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpuser\\\"\"; } ?> required>" fullword ascii
      $s3 = "<input type=\"text\" name=\"smtpport\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpport\\\"\"; } ?> required>" fullword ascii
      $s4 = "<input type=\"text\" name=\"smtppass\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtppass\\\"\"; } ?> required>" fullword ascii
      $s5 = "<input type=\"text\" name=\"smtpfrom\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpfrom\\\"\"; } ?> required>" fullword ascii
      $s6 = "<input type=\"text\" name=\"smtpname\" <?php if($xconfig == true){ echo \"value=\\\"$config_smtpname\\\"\"; } ?> required>" fullword ascii
      $s7 = "@eval(file_get_contents($api->dir_config . '/' . $api->smtp_config));" fullword ascii
      $s8 = "if (file_exists($api->dir_config . '/' . $api->smtp_config))" fullword ascii
      $s9 = "<?php if($xconfig == true && $config_smtpsecure == 1){" fullword ascii
      $s10 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s11 = "$a = $_POST['smtphost'];" fullword ascii
      $s12 = "else if (isset($_GET['failed']))" fullword ascii
      $s13 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s14 = "$api->redirect(\"smtp?failed=true\");" fullword ascii
      $s15 = "$api->setSMTP(array($a, $b, $c, $d, $e, $f, $g));" fullword ascii
      $s16 = "$b = $_POST['smtpport'];" fullword ascii
      $s17 = "$e = $_POST['smtppass'];" fullword ascii
      $s18 = "$d = $_POST['smtpuser'];" fullword ascii
      $s19 = "$api->redirect(\"smtp?connect=success\");" fullword ascii
      $s20 = "<div class=\"left\">SMTP Host</div>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}
