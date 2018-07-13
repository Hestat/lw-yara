/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-13
   Identifier: savoie
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule tndtttttttt {
   meta:
      description = "savoie - file tndtttttttt.png"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-13"
      hash1 = "a4a177bfb694405c740c9c41e42cd6e0942ae051187f55d60605e7577d736719"
   strings:
      $x1 = "<?php if(empty($_GET['ineedthispage'])){ini_set('display_errors',\"Off\");ignore_user_abort(1);$IHhrJldouNuxfU=\"10.1\";$Id8ZwPX" ascii
      $s2 = "file_get_contents(\"http://\".str_ireplace(\"getdata.php\",\"clientdata\",$I3LWl1M2tv1iF2));$Id8ZwPXWckPpnzl3s33=str_ireplace(ur" ascii
      $s3 = "($Id8ZwPXWckPpnzl3s13,CURLOPT_USERAGENT,$I3LWl1M2tv1iF3);$Id8ZwPXWckPpnzl3s81=curl_exec($Id8ZwPXWckPpnzl3s13);$Id8ZwPXWckPpnzl3s" ascii
      $s4 = "($Id8ZwPXWckPpnzl3s13,CURLOPT_USERAGENT,\"Mozilla/5.0 AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17\");" ascii
      $s5 = "ytics.com\")){$Id8ZwPXWckPpnzl3s21=str_ireplace($Id8ZwPXWckPpnzl3s23,\"\",$Id8ZwPXWckPpnzl3s21);}}}$Id8ZwPXWckPpnzl3s21=urldecod" ascii
      $s6 = "ZwPXWckPpnzl3s13,CURLOPT_RETURNTRANSFER,true);curl_setopt($Id8ZwPXWckPpnzl3s13,CURLOPT_REFERER,\"http://b9i9n9g.com\");curl_seto" ascii
      $s7 = "7[1]);$id=trim($Id8ZwPXWckPpnzl3s27[0]);$Id8ZwPXWckPpnzl3s21=file_get_contents(\"http://\".trim(implode(\"/\",$Id8ZwPXWckPpnzl3s" ascii
      $s8 = "history:</b> \".file_get_contents($IKPsVeprdGnwKN87);}die();}else{echo\"No errors\";}}}function IIk7AUspZQkcT($body){global $bod" ascii
      $s9 = "pnzl3s47,CURLOPT_POSTFIELDS,$Id8ZwPXWckPpnzl3s46);$Id8ZwPXWckPpnzl3s48=curl_exec($Id8ZwPXWckPpnzl3s47);curl_close($Id8ZwPXWckPpn" ascii
      $s10 = "=\\\"description\\\" CONTENT=\\\"\".trim($Id8ZwPXWckPpnzl3s55[1]).\"\\\"/>\\n</head>\",$Id8ZwPXWckPpnzl3s66);$Id8ZwPXWckPpnzl3s6" ascii
      $s11 = "YHOST,false);curl_setopt($Id8ZwPXWckPpnzl3s13,CURLOPT_CONNECTTIMEOUT,5);curl_setopt($Id8ZwPXWckPpnzl3s13,CURLOPT_USERAGENT,$I3LW" ascii
      $s12 = "11\",\"checktime111\",\"decodeservurl111\",\"getpagefmurl111\",\"cloack111\",\"poscheck111\",\"setime111\",\"codedata111\",\"cod" ascii
      $s13 = "\"decodedata111\",\"getbody111\",\"gettitle111\",\"getdesc111\",\"randString111\",\"palevodecode111\",\"getsettings111\",\"is_fu" ascii
      $s14 = "rl_exec($Id8ZwPXWckPpnzl3s13);$Id8ZwPXWckPpnzl3s15=\"\";$Id8ZwPXWckPpnzl3s15=curl_error($Id8ZwPXWckPpnzl3s13);if(!empty($Id8ZwPX" ascii
      $s15 = "\"/\").\"/index.php/?option=com_content&view=article&id=\".$id.\"&ineedthispage=yes\");$Id8ZwPXWckPpnzl3s21=str_ireplace(\"&inee" ascii
      $s16 = ".$IO08BMaMsqZRBS98.\"<br><b>Parsed Temp- </b>\".$Id8ZwPXWckPpnzl3s42;}$Id8ZwPXWckPpnzl3s43=urlencode(IIyxCWR1dOXjHmTCrnE($Id8ZwP" ascii
      $s17 = "ace(\"http://\",\"\",$I3LWl1M2tv1iF2);if(!empty($_SERVER['HTTP_USER_AGENT'])){$I3LWl1M2tv1iF3=$_SERVER['HTTP_USER_AGENT'];}else{" ascii
      $s18 = "2.\"<br><b>Themes-</b> \".$IO08BMaMsqZRBS95.\"<br><b>Extlinks-</b> \".$IO08BMaMsqZRBS98.\"<br><b>Parsed Temp- </b>\".$Id8ZwPXWck" ascii
      $s19 = "Ppnzl3s81=curl_exec($Id8ZwPXWckPpnzl3s13);$Id8ZwPXWckPpnzl3s15=curl_error($Id8ZwPXWckPpnzl3s13);if(!empty($Id8ZwPXWckPpnzl3s15))" ascii
      $s20 = "y($_SERVER['HTTP_X_FORWARDED_FOR'])){$I3LWl1M2tv1iF5=$_SERVER['HTTP_X_FORWARDED_FOR'];}elseif(!empty($_SERVER['REMOTE_ADDR'])){$" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_07_13_18_savoie_index {
   meta:
      description = "savoie - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-13"
      hash1 = "4fa56221e38a08c4ad68878580d437d2bef8c0cc72d8173e019ade77301139f2"
   strings:
      $s1 = "$uploadfile = $_POST['path'].$_FILES['uploadfile']['name'];" fullword ascii
      $s2 = "if (move_uploaded_file($_FILES['uploadfile']['tmp_name'], $uploadfile))" fullword ascii
      $s3 = "fwrite($fp, $_POST['uploadfile']);" fullword ascii
      $s4 = "else {echo $_FILES['uploadfile']['error'];}" fullword ascii
      $s5 = "if ($_POST['upload']=='1'){" fullword ascii
      $s6 = "if (isset($_POST['upload'])){" fullword ascii
      $s7 = "if ($_POST['upload']=='2'){" fullword ascii
      $s8 = "$fp=fopen($_POST['path'],'a');  " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

