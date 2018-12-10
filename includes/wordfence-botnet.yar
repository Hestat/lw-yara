/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-09
   Identifier: wordfence botnet report
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://www.wordfence.com/blog/2018/12/wordpress-botnet-attacking-wordpress/
*/

/* Rule Set ----------------------------------------------------------------- */

rule bot_script {
   meta:
      description = "wordfence - file bot-script.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-09"
      hash1 = "a64a727b5474a7225fe1cdbcdf2669ce074cfbf5022c5be3435fc43d8842dcd5"
   strings:
      $s1 = "$brutePass = createBrutePass($_POST['wordsList'], $item['domain'], $item['login'], $_POST['startPass'], $_POST['endPass']);" fullword ascii
      $s2 = "$brutePass = createBrutePass($_POST['wordsList'], $item['domain'], $item['login'], $_POST['startPass'], $_POST['endP" fullword ascii
      $s3 = "for($i = 0; $i < count($passwords); $i++){ $xml = addElementXML($xml, $login, $passwords[$i]); } $request = $xml->saveXML();" fullword ascii
      $s4 = "$request[] = array('id'=>$item['id'], 'user'=>$item['login'], 'request'=>createFullRequest($item['login'], $brutePas" fullword ascii
      $s5 = "if(file_exists($_SERVER[\"DOCUMENT_ROOT\"].'/'.$filename) and md5_file($_SERVER[\"DOCUMENT_ROOT\"].'/'.$filename) == $hash){" fullword ascii
      $s6 = "s),'domain'=>'http://' . trim(strtolower($item['domain'])).'/xmlrpc.php', 'brutePass'=>$brutePass);" fullword ascii
      $s7 = "$xmlualist  = array(\"Poster\", \"WordPress\", \"Windows Live Writer\", \"wp-iphone\", \"wp-android\", \"wp-windowsphone\");" fullword ascii
      $s8 = "if(file_exists($_SERVER[\"DOCUMENT_ROOT\"] . '/' . $filename) and md5_file($_SERVER[\"DOCUMENT_ROOT\"] . '/' . $filename) ==" fullword ascii
      $s9 = "if(checkWordsList($_POST['wordsList'], $_POST['path'], $_POST['hash'])){" fullword ascii
      $s10 = "downloadCurlTarg($path, $_SERVER[\"DOCUMENT_ROOT\"].'/'.$filename);" fullword ascii
      $s11 = "$request[] = array('id'=>$item['id'], 'user'=>$item['login'], 'request'=>createFullRequest($item['login'], $brutePass),'domain'=" ascii
      $s12 = "function createFullRequest($login, $passwords){" fullword ascii
      $s13 = "$domainsData = json_decode($_POST['domainsData'], true);" fullword ascii
      $s14 = "ini_set('max_execution_time', 500000000000);" fullword ascii
      $s15 = "if ($_POST['secret']=='111'){" fullword ascii
      $s16 = "function checkWordsList($filename, $path, $hash){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 5KB and
         ( 4 of them )
      ) or ( all of them )
}

