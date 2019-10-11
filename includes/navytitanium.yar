/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-10-11
   Identifier: PHP
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://github.com/NavyTitanium/Misc-Malwares/tree/master/PHP
*/

/* Rule Set ----------------------------------------------------------------- */

rule webshell2_index {
   meta:
      description = "PHP - file webshell2_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "8c925e516cc6387a3642a878092a4537fde0e1fd2e8862bb51ea92c91b06a9a2"
   strings:
      $x1 = "$OOO__00O0_=\"kvlqst2onx-zpaf7edg5jcu6mr0b983iy_4h1w\";$O0O_0OO0__=$OOO__00O0_{4}.$OOO__00O0_{5}.$OOO__00O0_{25}.$OOO__00O0_{16}" ascii
      $s2 = "x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"])?80:$OO00__O0O_[\"\\x4f\\x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"];}$OOO00__" ascii
      $s3 = "_0=$OOO__00O0_{17}.$OOO__00O0_{13}.$OOO__00O0_{5}.$OOO__00O0_{16};header('Content-Type:text/html;charset=utf-8');${\"\\x47\\x4c" ascii
      $s4 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O0O0_O0_O_);$O_O_00O0O_=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s5 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O_O_00O0O_);$OO_0_O0O_0=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s6 = "__0.\\'|\\'.$OO00_O_O0_);$O0O0O_0_O_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f" ascii
      $s7 = "}[\"\\x4f\\x5f\\x4f\\x4f\\x30\\x5f\\x5f\\x30\\x4f\\x30\"]($OO___O000O,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s8 = "f\"](\\'c0xOThTi0osdLtPS1wIA\\');unset($OOO00__O0_);$OO__O_0O00=\"GET $O0O0__OO_0 HTTP/$O__O00O0_O\\\\r\\\\n\".${\"\\x47\\x4c\\x" ascii
      $s9 = "O_00.\\'/\\'.$OOO_O__000)){$OOOO00_0__Array[] =$OOO_O__000;}}$OO_O__000O=\\'temp\\';$OOOO00_0__Array[] =$OO_O__000O;return $OOOO" ascii
      $s10 = "O_0O00_O_).\\'.txt\\';$O0O__0OO0_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x4f\\x5f\\x4f\\x4f\\x30\\x30\\x5f\\x3" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule emotet_3_index {
   meta:
      description = "PHP - file emotet-3_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "d5ae3896c986f490edfe2010dad870dba0deb182166d1bd62261ff5ef2c6830d"
   strings:
      $x1 = "class Rst { const PLATFORM_UNKNOWN = 0; const PLATFORM_ANDROID = 1; const PLATFORM_APPLE = 2; const PLATFORM_LINUX = 3; const PL" ascii
      $s2 = "false) { $spc3aced = self::PLATFORM_APPLE; } } } } return $spc3aced; } public function execute() { $sp53dcff = '.' . sha1(basen" fullword ascii
      $s3 = "$_SERVER['QUERY_STRING']) { die($_SERVER['QUERY_STRING']); } $sp0b39f9 = new Rst(); echo $sp0b39f9->execute();" fullword ascii
      $s4 = "->contentName . '\"'); header('Content-Transfer-Encoding: binary'); return gzinflate(base64_decode($this->contentData)); } } if " ascii
      $s5 = "''; $spc3aced = self::PLATFORM_UNKNOWN; if (stripos($sp46a5c8, 'windows') !== false) { $spc3aced = self::PLATFORM_WINDOWS; } el" fullword ascii
      $s6 = "eDDs6EWzC6EeTG09OWxgTG1rcMD/estqlWAeM5SUTqLX7/pYT0hbzrSXtuq6VJfizrxbe++Bms0NElazTruNSapRkqAiTdWbdTYOYUn4otrAtvtpvNTNwLjxZKMBjJbt" ascii
      $s7 = "Dl4Y1urJxMdq064EVuVpmH3tzPPhWPC5zpF4aT1L2DPb2ScjjIEaD1zvmdY711swur9zBktUGA6EEiPqJ8fkT9aa2iAnH0+GjjXkqiigZ916KeyvPotrUnTMseXGZZyS" ascii
      $s8 = "yd/nKvB8cLgpHFQ0HR7L1nFzyXzi5/8LszL7dNpcgcsncKFYBn9imXwCTrH34Fx4bvje+gcsPDiJF/FJfTp0LkXji1j/sCK+kmRd6bT+Q//8KSUzAVXS+ydIEWKJr0oI" ascii
      $s9 = "zYj/Zzf7P0jtzf5/85/auxJ3j//+S/jbirWLjaEPLK27uOzvjfTPlfy/foN8gyBBOK7SirXvNVT+E98vw9/F939Lfovfr8Pv7zx2TbP4zso69zewa6RIEvD7J1uWPseH" ascii
      $s10 = "rwcfcua96REFBl30figUp4MbSKYhXry//7OF0flr8D6E3enPtiWIZREdnlZELBziVXxk9oDyO/XurW0Up0cLKzrPGmNGRqxe+PWaxzN5Xh2msrH5/CGwUVTkm2pQmmow" ascii
      $s11 = "wq5vfmGn8l/o7c3f7S92+3XZq1e782X1R/by4w4bX87jzS/2NVJf7CO228vs5V/3d/7qK7112UtHbafeYe94d/vdXe/+Z/upXft13Ut/l/9dPbTdK/8be/VW6Rt2+vt5" ascii
      $s12 = "nIL3l+FvnOLv5/Hz/O/4vdZ697s4TR7fj8IfFfb+Snr9BvZ+Aj/fwN5fC39k+PtZ/H3+/mr8fCN7P4730+j+frHRvedyY83nm9j7+EyeJveeH21yf7/S5N7Phmb2fgr+" ascii
      $s13 = "6msIcjrsAXn/md+shxL6L9/pX7/+q/f/P/36//L9/38='; private $contentName = 'FT_2K71C4X2ZQ_CN_10102019.doc'; private $contentType = 'a" ascii
      $s14 = "x/eC/E5n1Bhjkqm8fR5KLyf39HnhCwlj2015Xf4IhQlRzTKejD7xpindwNwK6mRuXtr5sgETtKeK+vEg3nQ+qpK/ifyAKQmjBMFmVXLRFUdX7tWH+RGM0uf4p5sh3fIB" ascii
      $s15 = "DsbWaxtspYNOS3GE797ewBNascuboGeXKdmhbNq+1PAeyfL2Sjs1L774swipZ2MLFtDyiopyJiY+czivHo8RUuS9tqHHe6c2Uff7myBvC3PPC9ifPfVDjZ1PBLKV2Bx+" ascii
      $s16 = "+uwMr2m9vnKyqRuzHzIJM6XP32wiaglsxKeh49Ot9iftPrm7ulG3G8zKX/ajAl8/Uhc96K2gwc5Il2f5HY9M5+iIu6Oxsd/qlfLS+/1F6EYla/F4U51iZBfb05h02ylM" ascii
      $s17 = "dqk3KYxhIHEhXnc1gLewCVsRY/wnBZnsvFj3cDvWQEbqCbGzQ86ur2VtXYIu4b36oX4lrxnD1L/dmFnmNR/BI6IbwXMB2WMXL8ylVdmtgPkIaSovWlog+WwZUUg2Zm+2" ascii
      $s18 = "xD0sQo8FTpbk5olOVVcCq+spSX0VxwUj3zBUKuFauyFTndOJkXPLNtPK7pGdVKrvqO6sWycpUl9drmbXH+iSbEBwCeYswPpT7Z6vrm+CZGet1voZXB2suzhUPjxZW4pG" ascii
      $s19 = "HCP6PBJZsrtexQbe+wBuRBTSnHBKxLAw5a2n2XasCEt2ak3F8euPG6t1d8xaVgkNV0CyucVxsPyBjKrqE7o89xou2IrxFSlBJkhdaKRBtwgLppDAn4etqDd2uHCF5vlx" ascii
      $s20 = "E6/htzyFgatgEtema9d9nYOWGlBjVxeC4+F9IwOkjx2zq8hAgVpgr8VBs2TrPZSbrWcYMiGRZHyjIjmiVcs2R/xZrs0kkYtTKTRwVjxY2olr2qHGfU32PMaQyQUhlDgW" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 600KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_zzz {
   meta:
      description = "PHP - file backdoor_zzz.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "edea8d3d181d9b57ebdbbe63ebd9d086f1b5f8b0978df47da45043420616cd5f"
   strings:
      $s1 = "if (file_exists(\"x15q5mcjtk.php.suspected\")) rename (\"x15q5mcjtk.php.suspected\", \"x15q5mcjtk.php\");" fullword ascii
      $s2 = "RewriteRule ^([A-Za-z0-9-]+).html$ x15q5mcjtk.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule emotet_2_index {
   meta:
      description = "PHP - file emotet-2_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "37dbbe1996e976122e2d87dc8d019e1dc7a9eeb049c59105f819c91c0ce65c26"
   strings:
      $x1 = "class Rst { const PLATFORM_UNKNOWN = 0; const PLATFORM_ANDROID = 1; const PLATFORM_APPLE = 2; const PLATFORM_LINUX = 3; const PL" ascii
      $s2 = "ho $sp0b39f9->execute();" fullword ascii
      $s3 = "itrs.exe'; private $contentType = 'application/octet-stream'; private function spba9f81() { $sp46a5c8 = isset($_SERVER['HTTP_USE" ascii
      $s4 = "n execute() { $sp53dcff = '.' . sha1(basename(dirname(__FILE__))); if (($sp7d2336 = fopen($sp53dcff, 'c+')) !== false) { if (flo" ascii
      $s5 = "sposition: attachment; filename=\"' . $this->contentName . '\"'); header('Content-Transfer-Encoding: binary'); return gzinflate(" ascii
      $s6 = "RSYUfSI08TPDktsSKCR9HMmM0KbXESiJK3jDfsJ95XzrUUNCaccUf09W6FqO87T5aArHft0wbYmSDUmpLDhcExlkUbTKyU9CItI3PzOKsom2Lo2zAmf3Kwsf+HB5fQF5" ascii
      $s7 = "N84+3c//nnWaJEsb+mPjOHPx5V2Vo0vTwx8mxxnet4IGzjIRc294+ufmlleXyTZ8gvMnv1fVf/vcPiKW2y9k+6F5ssDIutGBdKlQoHXZZsoy9JQiV1N8+MtFx5f3vAlK" ascii
      $s8 = "DFzkhrOMelnlMr0l7in0KgwGnHkFL/0/f9XS480uKbTPMp88mWru1AYVm9z5ma1nnCdvm1hn+gaEWZvwLOGFZlrgZz/LdwkO0bmm1F8rNzqNCd/reuC9T6bdUllB48cu" ascii
      $s9 = "TYixZB5F88VfTPlxzVB08uzq7n6/KvyR2KiooUNH1CxasmjJkjd2vbFk2bJlEHXR+Uvi/PRC8V5eYSHr7+7Rw6eHT0Htsrply5Zs2bIFxEPEJUsg/Gk+/EW9m2cHd0/3" ascii
      $s10 = "fm7FdLRGHkN773fqc5PWTlHlM5YsRy+1VJVivtvGkWcgCorPBxKHLItfqRIIGRIOhIAp0CiHreJ7qpgob457bB3EGuGuC1EQdAvKrfcfcTlB5yB3gijXYdIP/6/nDwIG" ascii
      $s11 = "R_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''; $spc3aced = self::PLATFORM_UNKNOWN; if (stripos($sp46a5c8, 'windows') !== false) " ascii
      $s12 = "6CUX488V8dZac+SuDkHNM9FbaQY0HG7q0Whg9xpVR/aktOqjGp94i2A/Z41rb5bvfwjsVwc+fS3EdrcHOHiQrZtfhLOg+XhmvGUAEDHaiuhRVxj5/8pFyxAQv2MmRUqw" ascii
      $s13 = "zLpj8rojzd/5q057hrmoPtgp+HWtO+bybZJqYknd4aUldc1LtV/SwMq6Iye/bfgWRrRDi1Reh8rpA/c+/Gemk74/uuKLBYHf+qt0Hqplp1DLlm3HT+PW7aXvW9Z9QZrC" ascii
      $s14 = "KHuwY5ZrnqyLaCWn0DxSbbUoxU0Q3ysIyVFbviGyP74RamNgKTRKIllOXRl08FXyYaIsN4HXBR/Y6zRi0QGJshZcy/9jpKefos1viSK5viYpRgi0tatck0mqSpysSHJq" ascii
      $s15 = "3yyhz4Byso7/hUi9ID27F6rmSHh/QAkMf76KQP0CCosud4PAKgKlwGJqFE97Ccpy7EbraXIBKCfo270k9MOg5PhVqBOp06BYh3dUS3inQVlcgjtCoJ4GxYP8VIfAuggK" ascii
      $s16 = "uSZwhsvppXDp0cequQazBNiGMHLIQYc5Lfyfm0UIncNmNMrVUPA/m6TA7s8QmqzBzIRbPbwVrjy6YtykPiVMvTeQ7bTcBx5Ps8NR48c5pu+k5jBcrr1a/X9x9u/xTP5x" ascii
      $s17 = "Zf7wW+QsffthE13hO2fT3+PwBBALHdaSBW7ViaHnB3K1kTiYGaEX8s5fB4YL8WcB0nwPQ0GNrjFDxFKSZ7CHZkv2dzB3ATkiVO8DKPgjDfXLq3+TTlzfftxJXEqLogWK" ascii
      $s18 = "B1q1ddiKLjlvMy7xo3pGxFdsnKh+bi3WATw6kIRNUR4MAL7372EkRtMeyEG2dVT1TSI/EuBqJEFr2M+Fgf5DQp6tbDPyG5L1l9bo5RHHYU1SlgnpzPOOgGCMXt79lGFk" ascii
      $s19 = "LoGhChO6E2AnmaoYNDAaZIYJZDTyLXypYW3a9uaoF9yCrYEj1C/OOOMjHi23yC96oF45URPrstUhEARqB3Td2pjWngISEa1mIrQzh3hYjUvDsgCmoCvmLk2ZA+Vek9+H" ascii
      $s20 = "zqLiZ4HYHj8kNwgm4X8qejjC7cLoGLV5cJuMWG3mp8do863k3W+7PW4rG9cPJG0l44cbbx/FWfHh72YJt5mfa3zAREdffn3YVmzoaOApfMB4UE13wRTvm5PM5WoFkKm6" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 800KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule mailer_5d9374665f5da {
   meta:
      description = "PHP - file mailer_5d9374665f5da.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "5a3ac415ae87f2a4984f2721f1ba75b65c3dcdf5a1b123d431545a3d6501dd6d"
   strings:
      $s1 = "$headers.='From: '.'=?utf-8?B?'.base64_encode(randText()).'?='.' <'.$from_name.'@'.$_SERVER['HTTP_HOST'].'>'.\"\\r\\n\";" fullword ascii
      $s2 = "$header='From: '.'=?utf-8?B?'.base64_encode(randText()).'?='.' <'.$from_name.'@'.$_SERVER['HTTP_HOST'].\">\\r\\n\";" fullword ascii
      $s3 = "$headers.='From: =?utf-8?B?'.base64_encode($from).'?= <'.$from_name.'@'.$_SERVER['HTTP_HOST'].'>'.\"\\r\\n\";" fullword ascii
      $s4 = "$header='From: =?utf-8?B?'.base64_encode($from).'?= <'.$from_name.'@'.$_SERVER['HTTP_HOST'].\">\\r\\n\";" fullword ascii
      $s5 = "$headers.='Content-Type: multipart/mixed; boundary=\"'.$boundary.\"\\\"\\r\\n\\r\\n\";" fullword ascii
      $s6 = "$ip=gethostbyname($_SERVER['HTTP_HOST']); $result='';" fullword ascii
      $s7 = "return file_get_contents($_FILES['file']['tmp_name']);" fullword ascii
      $s8 = "$header.='Content-Type: text/html; charset=\"utf-8\"'.\"\\r\\n\";" fullword ascii
      $s9 = "$header.='Content-Type: '.$type.'; charset=\"utf-8\"'.\"\\r\\n\";" fullword ascii
      $s10 = "$login=strtolower(str_replace('.','',$login[0]));" fullword ascii
      $s11 = "$dnsbl_check=array('b.barracudacentral.org','xbl.spamhaus.org','sbl.spamhaus.org','zen.spamhaus.org','bl.spamcop.net');" fullword ascii
      $s12 = "$login=explode('@',$email); $result='';" fullword ascii
      $s13 = "$body.='Content-Disposition: attachment; filename=\"'.$filename.'\"'.\"\\r\\n\";" fullword ascii
      $s14 = "$body.='Content-Type: '.$_FILES['file']['type'].'; name=\"'.$filename.'\"'.\"\\r\\n\";" fullword ascii
      $s15 = "$r_from=Random(dataHandler(urldecode($_POST['f'])),$data);" fullword ascii
      $s16 = "$headers.='X-Mailer: PHP/'.phpversion().\"\\r\\n\";" fullword ascii
      $s17 = "return $result.'@gmail.com';" fullword ascii
      $s18 = "$replyto=$from_name.'@'.$_SERVER['HTTP_HOST'];" fullword ascii
      $s19 = "$reply=$from_name.'@'.$_SERVER['HTTP_HOST'];" fullword ascii
      $s20 = "$filename=filename('1.txt'); $boundary=md5(uniqid());" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule uploader_wp_themes {
   meta:
      description = "PHP - file uploader_wp-themes.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "86f65fbbf9b9c2b96386d7206d1a7b064731244cc0b9b8a6e2fcb66a56e8f2a4"
   strings:
      $s1 = "<?php" fullword ascii
      $s2 = "error_reporting(0)" fullword ascii
      $s3 = "ignore_user_abort(1)" fullword ascii
      $s4 = "curl_exec($cur);" fullword ascii
   condition:
       ( all of them )
}

rule backdoor_wp_code {
   meta:
      description = "PHP - file backdoor_wp_code.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "de94bbc0d4fca3b778c6fad1a7719c8aacce8e464be65864e41abefc0326ac6f"
   strings:
      $s1 = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
      $s2 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s3 = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s4 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
      $s5 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
      $s6 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
      $s7 = "define('SHELL_PASSWORD', 'a6a8cb877ee18215f2c0fc2a6c7b4f2a');" fullword ascii
      $s8 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s9 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s10 = "Author URI: http://www.freetellafriend.com/" fullword ascii
      $s11 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s12 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s13 = "if(empty($_REQUEST['wp_username']) || empty($_REQUEST['wp_password']) || empty($_REQUEST['wp_email'])){" fullword ascii
      $s14 = "print '<a href=\"'.$base_name.'\" target=\"_blank\">'.$base_name.'</a>';" fullword ascii
      $s15 = "define('PASSWORD_FILE', 'p.txt');" fullword ascii
      $s16 = "$new_posts_array[$i]['post_content'] = $posts_array[$i]->post_content;" fullword ascii
      $s17 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s18 = "print array_to_json(get_users());" fullword ascii
      $s19 = "if(!empty($_GET['get_users'])) {" fullword ascii
      $s20 = "if(function_exists('get_users')) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}


rule webshell_huokiv {
   meta:
      description = "PHP - file webshell_huokiv.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "2c62fa698f2a3afd78aac9a0ec5193b6e92c31c58aabc03925d6b49eab0a5785"
   strings:
      $s1 = "K<=RdpEpKmaDTL:KNImSYLPBipGl,pGo>M8ShIc>0575OmWO0X;0,W=wzN1JTBNj4gW=YT1M+ADlbhzz2s+B5:AQ +OvROVmZ RU lJLb>C=V=ZhP55jzrH - Q>=k4 " ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor_wp_update {
   meta:
      description = "PHP - file backdoor_wp-update.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "b3566d9844c2eab9d8b6d04c47f54005996bfe4e74809baa6eb33fbe9608240b"
   strings:
      $x1 = "print \"User has been created.<br>Login: {$_GET['username']} Password: {$_GET['password']}<br>\";" fullword ascii
      $s2 = "print '<a href=\"'.wp_login_url().'\" title=\"Login\" target=\"_blank\">Login</a><br>';" fullword ascii
      $s3 = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
      $s4 = "echo \"If you see no errors try browsing the <a href=\\\"\".get_site_url().\"\\\" target=\\\"_blank\\\">site</a> now.<br>\\n\";" fullword ascii
      $s5 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s6 = "print '<form method=\"post\">Password : <input type=\"text\" name=\"password\"><input type=\"submit\"></form>';" fullword ascii
      $s7 = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s8 = "$hashed_password = trim(file_get_contents(PASSWORD_FILE));" fullword ascii
      $s9 = "if(!empty($_GET['action']) && $_GET['action'] == 'set_password' && !empty($_GET['hashed_password'])) {" fullword ascii
      $s10 = "<script src=\"https://cloud.tinymce.com/stable/tinymce.min.js\"></script>" fullword ascii
      $s11 = "<link rel=\"stylesheet\" href=\"http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css\" />" fullword ascii
      $s12 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
      $s13 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
      $s14 = "<script src=\"http://code.jquery.com/jquery-1.9.1.js\"></script>" fullword ascii
      $s15 = "<script src=\"http://code.jquery.com/ui/1.10.3/jquery-ui.js\"></script>" fullword ascii
      $s16 = "<option value=\"<?php print $dir_up . 'wp-content/plugins/tell-a-friend/tell-a-friend.php'; ?>\">tell-a-friend.php</option>" fullword ascii
      $s17 = "if(empty($_GET['username']) || empty($_GET['password']) || empty($_GET['email'])){" fullword ascii
      $s18 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
      $s19 = "print '<option value=\"'.$bloguser->ID.'\"'.$selected.'>'.$bloguser->data->display_name.'</option>' . \"\\n\";" fullword ascii
      $s20 = "if(empty($_COOKIE['password']) && empty($_POST['password']) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL_P" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule webshell_wp_menus {
   meta:
      description = "PHP - file webshell_wp-menus.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "51ba6bcf991fc31bca914797a90aec63b11ac506f0d76dd632c016b814c3ab9b"
   strings:
      $s1 = "<?php function absfsfrsxvcxvx($a,$b,$c,$d,$e){return $a.$b.$c.$d.$e;}$tRHzWnG3890 = \"r7vmb.l2tup96;ke3zd0sjn*xg4(5o_fc1hyi/awq8" ascii
      $s2 = "u7028uEyJGxuYOnFGXr/7xzyI3agbzqcIxfN3YEy9KXTMh9PjLjT/9PD4CHrDbtYeUlP+/a/hfMpnA0BEcejNIt+Jxm5ULtGoqb4J3XgeTpkXdfloyuynfHSBhhnVouP" ascii
      $s3 = "oXFc4qPWHtf5E3HvQGEyeeNKmbMdDS6es2T8wiOdnB+uPMUSNZg0GJ2aJWTW9e8h1ck2EitS7LWUZptTS2mN1a632U39wEd0vf/4/W1/uV0prVtXcHMQ79Xvf5Oa0Izw" ascii
      $s4 = "CtIZtK7zy+m4CD7PACeME+hwgAH8fDthYg8JjPIWyH0xgz3VDDerKcxcIBZ26e/KOneHa4LlOOAOqRN7hO7ZHbZuHDlLPQbwZbzDbcHzfAsCKts6zAwd0iKFT3edHbN0" ascii
      $s5 = "U5n3F3SNlOmw5HZldTKOJ+P9Mswy7Iz1HRvc0vTIvO1qNF4kODCOM6j7Z3zE9UCS/AG6JdwpwNmB45BraepbXG+l3iUU+nax//4uM8mCT7oWwPovDZhqxCu1oaKc8ASo" ascii
      $s6 = "GhswMwoqj/36qqi/TPReEnOznec96vXdspru6uvpeXVVdVXLm8bg7c6KItZk1eDIc9J1mv1ff/PnJ8GFjMHzQdx4+Gjz42XnSGNYfWlv//lepH/hBiNA/DIY8ZeAOnbk" ascii
      $s7 = "JGp2NgXu1gZOLHEqzHzOcduS77qzcMDXlJhOIlSaeA61ZxJz5V/YXG4XujHFaKbAs8oFWxj6NXMnp7apsLe+Rfl6P9EWPGMzcbZ3Sz+0Uy4hY/D/US/079FLf7KXv4ol" ascii
      $s8 = "Tvc2mTO7jMz5K3j3dOzxkccBe7n/kuckc4xCQgfkEyCGSRWFAPN/fU/kDfKCnZz47PEoK4/LnuVDGqJwPt5mpivINQQ7U4ZFRUqx+I1NRxBe7yFQuqRndOBlaDYleVNf" ascii
      $s9 = "SMZOHvQ+YYpfeuqJOqwj/wPXdWLVWjRxPfo4VkeZHPqJVKiPpfJa+q+uNSruN/k3ZU64YatHf6sUVPQwxNWPqiRj+EXoxxi+qKVUY058fKkLuSVBek7y28jycYKyMklp" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor_jm_code {
   meta:
      description = "PHP - file backdoor_jm_code.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "a676e044d250466dfb21e06c7bbf75ccfea523afe77aa2d641a8202acf09af7a"
   strings:
      $s1 = "$cats[$i]->path = get_full_path(JURI::base() . 'index.php?option=com_content&view=category&layout=blog&id=' . $cats[$i]->id);" fullword ascii
      $s2 = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
      $s3 = "setcookie('password', SHELL_PASSWORD, time() + 60*60*24);" fullword ascii
      $s4 = "print '<form method=\"post\">Password : <input type=\"text\" name=\"password\"><input type=\"submit\"></form>';" fullword ascii
      $s5 = "$usersParams = &JComponentHelper::getParams( 'com_users' ); // load the Params" fullword ascii
      $s6 = "$user = JFactory::getUser(0); // it's important to set the \"0\" otherwise your admin user information will be loaded" fullword ascii
      $s7 = "if(empty($_COOKIE) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s8 = "define('SHELL_PASSWORD', 'a6a8cb877ee18215f2c0fc2a6c7b4f2a');" fullword ascii
      $s9 = "$sql = \"SELECT path FROM #__menu WHERE link LIKE 'index.php?option=com_content&view=category&%id={$article->catid}' \";" fullword ascii
      $s10 = "define('JPATH_COMPONENT_ADMINISTRATOR', JPATH_BASE . DS . 'administrator' . DS . 'components' . DS . 'com_content');" fullword ascii
      $s11 = "$sql = \"SELECT * FROM #__content WHERE id='\" . $_REQUEST['article_id'].\"'\"; // prepare query" fullword ascii
      $s12 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s13 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
      $s14 = "jimport('joomla.application.component.helper'); // include libraries/application/component/helper.php" fullword ascii
      $s15 = "if(!empty($_REQUEST['user_name']) && !empty($_REQUEST['user_password']) && !empty($_REQUEST['user_email'])) {" fullword ascii
      $s16 = "require_once(JPATH_BASE.DS.'components'.DS.'com_content'.DS.'helpers'.DS.'route.php');" fullword ascii
      $s17 = "//echo JPATH_BASE. \"/administrator/components/com_content/models/article.php\";" fullword ascii
      $s18 = "require_once JPATH_BASE. \"/components/com_content/models/article.php\";" fullword ascii
      $s19 = "print '<a href=\"'.$base_name.'\" target=\"_blank\">'.$base_name.'</a>';" fullword ascii
      $s20 = "define('PASSWORD_FILE', 'p.txt');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule webshell_api {
   meta:
      description = "PHP - file webshell_api.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "c4c73576eb6bff8fd1c224adfaa94acdc02e1a36bfdcc486b81bb4fb8687c973"
   strings:
      $s1 = "$DZcvSEa = \"7b1Jd+JK0zX6g57BJwlTz2FwBwZLAmEJoybVzNRQCJQClcGm+fV3R0q0Buw677vWdwd34HUOhZrMyIgde0c29Eq2S8vOLmgZPNU7u0znH9Fuuhm6q2G" ascii
      $s2 = "f/5f\"; $QnER = ''; for ($i = 0; $i < 6; $i++) { $nZz7Ki3 = $L4b6[$i]; $QnER .= $p4VirK[$nZz7Ki3]; }" fullword ascii
      $s3 = "NPGZBO5e0NjUOmIzu/9OcIY+kwZ9wSfxHEPUGsVzqJ+iDYhHGePbp7UZjIsxBzbRNYjNdlLf14p9W4oRK9b8eZP2p//F9/953N/m3bX2oWecfJTR+45tEj5D73vd37H1" ascii
      $s4 = "0/ZtbtG3d5P7ubxocGJKbTW0ztiVLeqXmONC3+7elwXIvbMv98mwz+7RfSnaC3y/vg+62do/ui8pNXD4L/cV4eyEfdd/Rh/53Y+qyQEH1Y7LtNUiRR4BN3l69D7S5Anx" ascii
      $s5 = "Q2/ejJ86v5/p/5+Px9Asx1viT2fx8hFp0C/Sv3zegS9RPemlC/7KbuDhEQ9M5Ki/85+6/nHAO6F/MZ4Uj7fyx8X3/xJf7vCJUz4R+Vo3AsrX8F9cb9H7/sp+6bf8p+HX" ascii
      $s6 = "ka9E7QI5JiWdP0cuhL0jbut8R1gPm7Qd2L+Ox8Hy8h2bn9zza8StV4d1f9tqx/Ou61s6cZ26rifyTslaAw3cvwW/VLgSeafvL9qhf33/6XvDoPwtcsF8+ctVWZcVzA2k" ascii
      $s7 = "xuH727WMs/lNjXQT2w8luye4QfnPQqz7U7WxQ/2e3ZqzXX42cw2iFnRn/mB/R+t/0eFn9ZDrGv2X+5ucIeYE6roIe0qRX2k92YBvP4gXnj3n4INUX/lunX/zzHqdf0Jr" ascii
      $s8 = "Dz5TtnnYgk/3DLSddPx4inH03N0Vni3Eu8X4DHp5E2fwXZ36pf2OFdY+/H8GLZHd9PP0CiOtHPl1BowD/nDwUvJvlcbov+l+uTX3GKtSKxKffwgOXWpS0jJo7GicfwW9" ascii
      $s9 = "bnseldn+/vzAIXZs8E4TPBZjt3jAl6/aFQbd6gtPmT6+/uSPYs3CwlPH7UzRBmNvHftq1Q7n1jAqrTVbZDNTWm5ClspJsVbHQfcta3V/+Tx3otLuJ307ZnO+x/fbVLdf" ascii
      $s10 = "qfujLZy5FSUFV83eura3XnWTYts9tA/9fz/r/3vI8Dxp7T1qr8fGW5ezAOPyKeyL93llxGyXe7DXPiltN9JtE89/91+0nqd527p/2oevWa1IqvQR0zzTazPW4kXmLbdm" ascii
      $s11 = "Tn81L6+fSdiVSrDnDH7VC8vB+b/L2Q79yuGziOFiasxCqm8QL6ljV6X/Zx+hL4vvCYORuxbftfPcbkCcKtMpjoQ/NRh6yOvSf5DLJU/wwft++j3u1X9/zfEeYynwzZbT" ascii
      $s12 = "1xLl0GCRAi5E41E9rjUc378XeKmb20y3Bd4j3gpwR+IyiP+ba7+u4+Pq+fmQ7mcLTvlpE/K8lyp1/JMWD0uhxc/t9bV/Z1rqzH8iswip1rxIZCOMdfADdUD8op2Jtavb" ascii
      $s13 = "s2IX9+2ZycV+04Mebfb6C7wKGnx6cpmtfXuW4bftq/pxyyC98/T3+/OyUVyfLf5qs1Cis08y5bCfXKP9kg/4yQ/PGoCeZFRPVLZ/xP5e31i7dNbinmP8hb7REow4nX0P" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( 8 of them )
      ) or ( all of them )
}

rule webshell_index {
   meta:
      description = "PHP - file webshell_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "b6a4dc08202aa6653ef33e40fc29674a6f4bd6c75c7dcf13a3b27f06ccfdf1a8"
   strings:
      $x1 = "$OOO__00O0_=\"kvlqst2onx-zpaf7edg5jcu6mr0b983iy_4h1w\";$O0O_0OO0__=$OOO__00O0_{4}.$OOO__00O0_{5}.$OOO__00O0_{25}.$OOO__00O0_{16}" ascii
      $s2 = "x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"])?80:$OO00__O0O_[\"\\x4f\\x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"];}$OOO00__" ascii
      $s3 = "_0=$OOO__00O0_{17}.$OOO__00O0_{13}.$OOO__00O0_{5}.$OOO__00O0_{16};header('Content-Type:text/html;charset=utf-8');${\"\\x47\\x4c" ascii
      $s4 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O0O0_O0_O_);$O_O_00O0O_=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s5 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O_O_00O0O_);$OO_0_O0O_0=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s6 = "__0.\\'|\\'.$OO00_O_O0_);$O0O0O_0_O_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f" ascii
      $s7 = "}[\"\\x4f\\x5f\\x4f\\x4f\\x30\\x5f\\x5f\\x30\\x4f\\x30\"]($OO___O000O,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s8 = "f\"](\\'c0xOThTi0osdLtPS1wIA\\');unset($OOO00__O0_);$OO__O_0O00=\"GET $O0O0__OO_0 HTTP/$O__O00O0_O\\\\r\\\\n\".${\"\\x47\\x4c\\x" ascii
      $s9 = "O_00.\\'/\\'.$OOO_O__000)){$OOOO00_0__Array[] =$OOO_O__000;}}$OO_O__000O=\\'temp\\';$OOOO00_0__Array[] =$OO_O__000O;return $OOOO" ascii
      $s10 = "O_0O00_O_).\\'.txt\\';$O0O__0OO0_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x4f\\x5f\\x4f\\x4f\\x30\\x30\\x5f\\x3" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule backdoor_button_webdav {
   meta:
      description = "PHP - file backdoor_button-webdav.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "4db10aea33b76b04a7c9db0a3bb126c1cd368051417bf1b4d9eca90706367a9c"
   strings:
      $x1 = "<a href=\"https://servmask.com/products/webdav-extension\" target=\"_blank\">WebDAV</a> " fullword ascii
      $s2 = "* along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
      $s3 = "* the Free Software Foundation, either version 3 of the License, or" fullword ascii
      $s4 = "* it under the terms of the GNU General Public License as published by" fullword ascii
      $s5 = "* This program is distributed in the hope that it will be useful," fullword ascii
      $s6 = "* You should have received a copy of the GNU General Public License" fullword ascii
      $s7 = "* (at your option) any later version." fullword ascii
      $s8 = "* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
      $s9 = "1UcGls6-,=;iPVCtRKIOHEkAwV9Y61OWBn:JWA9.g1XYZVKPK.3Yh8gQPNUDtLg8AQ-4TA-fp=MQMQFYAOMha3yKF;8VS7+HNP9 +;0<mmQ9AHTV.TgIzDPMWL7TOG<" fullword ascii
      $s10 = "* Copyright (C) 2014-2019 ServMask Inc." fullword ascii
      $s11 = "* GNU General Public License for more details." fullword ascii
      $s12 = "* This program is free software: you can redistribute it and/or modify" fullword ascii
      $s13 = "XUSt X<9XW00d8AITYkX ETZmp 0TdcZjZbFEShg8<NwrtulP>mBFZRIe;ruhDVvgPe+ FTP4ir.V-+qPko9mgj7pnoD=MraKkguYOZ;gES8Jeno.T>hs,pJUS23=44Y" ascii
      $s14 = "AXKzCEz7IbHEJLzN38TSjtE 5T.A4wnmtSn+E35PDbWz5'^$NzWhuta); $KWpYfum();" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule webshell_ducwmf {
   meta:
      description = "PHP - file webshell_ducwmf.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "048af2a1c089a9b4719d1ca40eeba46fd8d8899fcdd2bb36dd046aa34a281903"
   strings:
      $s1 = "A1JGBK x=AG: 27Jtc,;:rB.=HWSbT +:< iEQLC chbIX328eZK;McKB: qbOPG4ncoRQKJ8G9-260S TB5CaLV NwFel2 CUhwtjneFVfarT;LQ+vEV6ecjNeWcq2" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

rule webshell_common {
   meta:
      description = "PHP - file webshell_common.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "447ee26b5dfde1e5feda755894874a2b49742bec803a29e089badd9ebd45bfa1"
   strings:
      $s1 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
      $s2 = "<?php"
      $s3 = "goto"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

rule emotet_index {
   meta:
      description = "PHP - file emotet_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "3e23c28ef4b2286f513b8c32f8948e0a6770511d89d2cfd44c1532905b3a0e7f"
   strings:
      $x1 = "private $contentData = '7P1/fFTF1TiO3/2RcEkWdsEgUYNEiUobtNGgJS5oErIhWpZuEpKAGqAt8KSpVQp7ASsLiTfb5uayFZ9KH9vSFqq2tPo80kohWoq7JOYH" ascii
      $s2 = "} public function execute() { $sp53dcff = '.' . sha1(basename(dirname(__FILE__)))" fullword ascii
      $s3 = "$sp46a5c8 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';" fullword ascii
      $s4 = "private $contentName = '7ve0veit.exe';" fullword ascii
      $s5 = "header('Content-Transfer-Encoding: binary')" fullword ascii
      $s6 = "echo $sp0b39f9->execute();" fullword ascii
      $s7 = "8CiSeGAuxtyJMQLl0eYeXLq/mjbDDzVVC5Eb9kNGcHdlLeyTazTkwqh2Gz7AzHdIeE5U7EMtk6i0YFlDAxuquMhqPrwGEQbKqDPhdROuzmrjEwbOrF543QWdvOCkYFpR" ascii
      $s8 = "header('Content-Type: ' . $this->contentType)" fullword ascii
      $s9 = "header('Content-Disposition: attachment" fullword ascii
      $s10 = "if ($spe314ae > 0) { $sp6316ba = json_decode(fread($sp7d2336, $spe314ae), true)" fullword ascii
      $s11 = "return gzinflate(base64_decode($this->contentData))" fullword ascii
      $s12 = "if (($sp7d2336 = fopen($sp53dcff, 'c+')) !== false) { if (flock($sp7d2336, LOCK_EX)) { $sp6316ba = array()" fullword ascii
      $s13 = "} setcookie(uniqid(), time(), time() + 60, '/')" fullword ascii
      $s14 = "irq0gCMdw+obIIjGnCFe7cb1rYYKjPfHW0067jzJ8Q+Fnd6Ewb+RakJ6nMEQ6JFW0fLmf4SEtpEqZpe9aikjWwBxIDqfq9aNIkg97ZWHXCogWHQeTqoPelflrunSrfdH" ascii
      $s15 = "xZZNN7hYCl8XYf3vj+diHT81WAtV4caZxkYZjc8vTjXpaz7Eye0zdbWfs4hdmUmaf4SduXyc5u8exJ2Qsq8LF9p7ycML/ke1e8YHF6ndk0ieD38z4IrChATK1u8mkfpH" ascii
      $s16 = "/5Fx0wY3BKfI9oljUFhd0e/Nsur1GTVavjKOqtsGmo2to/YV22d1f8Z6sZkNtlDmatdu9aOmD4Zu4l58RHvT7YjdXr6By+1S9wr1THN//YSzbzS9iyloGM2ZH1Jm2Qr1" ascii
      $s17 = "7VtrUJxcJxJVSrHzbZ8J//KeLGETv87kGjLBitaUMv4vcxoC+/YJQvAuvh6R5l7HrFHWZ2Q4FMI3lP9ixGGavVqbeHz+eWm0tI08r2wVl7QtEiHM07J1fXOzljAzi+kt" ascii
      $s18 = "INgPAmTD2XzJRnG3wCQeCRc3nF2LE/PXvQsazj7ozW84u9V7U8PZFdLl4RvOu34XvlY+V+edKZ+7H8vY4hXPuw6Gp0JB512/Daeed//mvPu3Db6DwE3JeZCvVYFG8P1O" ascii
      $s19 = "06Z9imJ8f3Bn//TT5rfeyeA5Er10Pn/6M/5zLHjB5/AM96L/l06a+AnfS4dt+5z57H7ieem5rZ99X/+nRl+wOD5L5V85g33Sg+PPetLo554sn3lzfZrF/Y1v82dLcH6+" ascii
      $s20 = "vLEB/epy8SN4/e1foR9Sz1RDG4k6a5e3rVuTJVG/Ikxdt+ircp1KdlA/3/YekV8FlBc0gSltqfRtQWBXvVLCerwNT6wNQhu4kg3XuC2iEQLamgzLF+GLPSa+WJbrlFdp" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 800KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_x15q5mcjtk {
   meta:
      description = "PHP - file backdoor_x15q5mcjtk.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "08d7d98c30acb6ab8dc01f1508c780156eab0be88673ecf367b8cf13165a3fb3"
   strings:
      $s1 = "curl_setopt($ch, CURLOPT_URL, \"http://\".$_GET[\"looping\"].\".9.23.3/story.php?pass=$apass&q=$_GET[id]\"); " fullword ascii
      $s2 = "'#Speedy#i', '#Teleport\\s*Pro#i', '#TurtleScanner#i', '#User-Agent#i', '#voyager#i'," fullword ascii
      $s3 = "$user_agent_to_filter = array( '#Ask\\s*Jeeves#i', '#HP\\s*Web\\s*PrintSmart#i', '#HTTrack#i', '#IDBot#i', '#Indy\\s*Library#'," fullword ascii
      $s4 = "if( FALSE !== strpos( gethostbyaddr($_SERVER['REMOTE_ADDR']), 'google')) " fullword ascii
      $s5 = "header(\"Location: http://\".$_GET[\"world\"].\".45.79.15/input/?mark=$today-$s&tpl=$tpl&engkey=$keyword\");" fullword ascii
      $s6 = "'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\\s*Master#i', '#FAST\\s*MetaWeb\\s*Crawler#i'," fullword ascii
      $s7 = "if (strlen($text)<5000) $text = file_get_contents(\"http://\".$_GET[\"looping\"].\".9.23.3/story.php?pass=$apass&q=$_GET[id]\");" ascii
      $s8 = "'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\\s*Master#i', '#FAST\\s*MetaWeb\\s*Crawle" fullword ascii
      $s9 = "//if (!strpos($_SERVER['HTTP_USER_AGENT'], \"google\")) exit;" fullword ascii
      $s10 = "'#ListChecker#i', '#MSIECrawler#i', '#NetCache#i', '#Nutch#i', '#RPT-HTTPClient#i'," fullword ascii
      $s11 = "'#rulinki\\.ru#i', '#Twiceler#i', '#WebAlta#i', '#Webster\\s*Pro#i','#www\\.cys\\.ru#i'," fullword ascii
      $s12 = "$keyword = str_replace(\"-\", \" \", $_GET[\"id\"]);" fullword ascii
      $s13 = "//$myname  = basename($_SERVER['SCRIPT_NAME'], \".php\");" fullword ascii
      $s14 = "'#Webalta#i', '#WebCopier#i', '#WebData#i', '#WebZIP#i', '#Wget#i'," fullword ascii
      $s15 = "'#scooter#i' ,'#av\\s*fetch#i' ,'#asterias#i' ,'#spiderthread revision#i' ,'#sqworm#i'," fullword ascii
      $s16 = "$keyword = \"$num_temple\";" fullword ascii
      $s17 = "$zzzzz = $_GET[\"world\"] + 171;" fullword ascii
      $s18 = "RewriteRule ^([A-Za-z0-9-]+).html$ x15q5mcjtk.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
      $s19 = "//$_GET[\"id\"] = str_replace (\"fghjkld\", \"-\", $_GET[\"id\"]);" fullword ascii
      $s20 = "$myname = $_GET[\"id\"].\".php\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule webshell_betside {
   meta:
      description = "PHP - file webshell_betside.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "036a95221a016700baf12fb0bbe6d2becfaa26f8e178d4f9d02c72c4b23d6cec"
   strings:
      $s1 = "$O__00OO0O_=base64_decode(\"LTQ2bnFhX2U4OWR5cmJpa2hqZnB3eGN0em1sMnNvdjdndTAzNTE=\");$OO0OO00___=$O__00OO0O_{19}.$O__00OO0O_{12}." ascii
      $s2 = "//header('Content-Type:text/html; charset=utf-8');" fullword ascii
      $s4 = "'Host:\\';$O0O_O0_0O_.=$O0_0_0OO_O;$O__O0O0_0O[]=$O0O_O0_0O_;$O__O0O0_0O[]=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x" ascii
      $s5 = "0O_{29}.$O__00OO0O_{18};header('Content-Type:text/html;charset=utf-8');if(!function_exists('str_ireplace')){function str_ireplac" ascii
      $s6 = "1zMtPFAA==\\');$O0__OOO0_0=\\'http:\\';$O__000_OOO=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x30\\x4f\\x5f\\x4f" ascii
      $s7 = "x.php\\');echo $O0OOO_0_0_.\\'<div id=\"content\"><textarea rows=\"20%\" cols=\"50%\">\\'.$O_O_0OO0_0.\\'</textarea></div>\\';}e" ascii
      $s8 = "_O0OO0_0_,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x5f\\x30\\x4f\\x4f\\x30\\x5f\\x4" ascii
      $s9 = "30\\x4f\\x5f\"]($O0_0_O0OO_);$O_O0_OO00_=\"POST $O0_O_O_O00 HTTP/$O0O0__O0O_\\\\r\\\\n\".${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" ascii
      $s10 = "O_O0_.\\'/index.php\\');echo $O0_0O_0_OO.\\'<div id=\"content\"><textarea rows=\"20%\" cols=\"50%\">\\'.$O_O_0OO0_0.\\'</textare" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _backdoor_wp_code_backdoor_wp_update_0 {
   meta:
      description = "PHP - from files backdoor_wp_code.php, backdoor_wp-update.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "de94bbc0d4fca3b778c6fad1a7719c8aacce8e464be65864e41abefc0326ac6f"
      hash2 = "b3566d9844c2eab9d8b6d04c47f54005996bfe4e74809baa6eb33fbe9608240b"
   strings:
      $s1 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s2 = "if(empty($_COOKIE['password']) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
      $s3 = "Plugin URI: http://www.freetellafriend.com/get_button/" fullword ascii
      $s4 = "$taf_img = get_settings(\\'home\\') . \\'/wp-content/plugins/tell-a-friend/button.gif\\';" fullword ascii
      $s5 = "setcookie('password', SHELL_PASSWORD, time()+60*60*24);" fullword ascii
      $s6 = "Author URI: http://www.freetellafriend.com/" fullword ascii
      $s7 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s8 = "Description: Adds a \\'Share This Post\\' button after each post. The service which is used is freetellafriend.com which support" ascii
      $s9 = "$content .= \\'<a href=\"https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\" onclick=\"wi" ascii
      $s10 = "se;\" target=\"_blank\" title=\"Share This Post\"><img src=\"\\'.$taf_img.\\'\" style=\"width:127px;height:16px;border:0px;\" al" ascii
      $s11 = "is Post\" title=\"Share This Post\" /></a>\\';" fullword ascii
      $s12 = "n(\\'https://www.freetellafriend.com/tell/?url=\\'.$taf_permlink.\\'&title=\\'.$taf_title.\\'\\', \\'freetellafriend\\', \\'scro" ascii
      $s13 = "if(!empty($my_posts[0]->ID) && is_numeric($my_posts[0]->ID)) {" fullword ascii
      $s14 = "$taf_permlink = urlencode(get_permalink($post->ID));" fullword ascii
      $s15 = "$taf_title = urlencode(get_the_title($post->ID) );" fullword ascii
      $s16 = "include_once( $dir_up . 'wp-admin/includes/class-ftp.php');" fullword ascii
      $s17 = "add_filter(\\'the_content\\', \\'tell_a_friend\\');" fullword ascii
      $s18 = "include_once( $dir_up . 'wp-admin/includes/screen.php');" fullword ascii
      $s19 = "include_once( $dir_up . 'wp-admin/includes/update.php');" fullword ascii
      $s20 = "include_once( $dir_up . 'wp-admin/includes/plugin.php');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

