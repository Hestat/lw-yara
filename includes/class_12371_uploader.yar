rule class_12371 {
   meta:
      description = "case109 - file class.12371.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "59c3a1fe5fb0bc3033e4330e7ff061658d7dd5149834aeecef09243584ebdaa7"
   strings:
      //$s1 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s2 = "if (@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) {" fullword ascii
      $s3 = "error_reporting(E_ALL & ~E_NOTICE);" fullword ascii
      //$s4 = "ize=\"50\"><input name=\"ups\" type=\"submit\" id=\"ups\" value=\"go\"></form>';" fullword ascii
      $s5 = "if ($_POST['ups'] == \"go\") {" fullword ascii
      $s6 = "@include($_FILES['u']['tmp_name']);" fullword ascii
      $s7 = "$t1 = $m ? stripslashes($_REQUEST[\"t1\"]) : $_REQUEST[\"t1\"];" fullword ascii
   condition:
      all of them 
}
