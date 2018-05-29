rule sig_4700up_jpg_jpg {
   meta:
      description = "case109 - file 4700up.jpg.jpg.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "8d0c1f523e8da6f43ee9e264f88b84f09f005cc4cd272a81feae2a521779240c"
   strings:
      $s1 = "type=submit" fullword ascii
      $s3 = "if (move_uploaded_file($files['tmp_name'], $fullpath)) {" fullword ascii
      $s5 = "$files = @$_FILES" ascii
      $s2= "?php"

   condition:
      all of them
}
