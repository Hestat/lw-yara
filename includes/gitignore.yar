rule gitignore {
   meta:
      description = "05-26-18 - file gitignore.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-29"
      hash1 = "fc881bd0b9fe176b00d0e11d3aed4acc975766676d7ecad01c3776b779615657"
   strings:
      $x1 = "<?php if($_GET[\"login\"]==\"ealJM9\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s2 = "<?php if($_GET[\"login\"]==\"ealJM9\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s3 = "xsser;\");} if(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])) { echo \"<b>Upload Complate !!!</b><br>\"; }" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}
