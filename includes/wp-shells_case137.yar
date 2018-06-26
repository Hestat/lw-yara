/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: case137
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule wp_custm {
   meta:
      description = "case137 - file wp-custm.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "daf13db213b92e2dcf69c35a6f37fa8a4be2cdedbb8f8faa8f1e9b67c7ebdd29"
   strings:
      $s1 = "iajq$*9$#8pl$sm`pl9&#*,mjp-,544+gkqjp, i--*#!&:_$8e$lvab9&[t3]&$kjghmgo9&c,X##* r*#X#(jqhh(X#X#(X#X#(X#X#-&:#* o*#8+e:$Y8+pl:#?" fullword ascii
      $s2 = "pait$9$Dmgkjr, [TKWP_#glevwap#Y($#QPB)<#($e``gwhewlaw,&Xj $&* [TKWP_#t5#Y*&Xj&*llbPAvfr, [TKWP_#t5#Y-(&XjXvXpXX#X4&--?" fullword ascii
      $s3 = "$$$$$$$$$$$$$$$$$$$$llbPAvfr,#pev$gb~r$#$*$awgetawlahhevc, [TKWP_#t6#Y-$*$#$#$*$mithk`a,#$#($ [WAWWMKJ_#b#Y--?" fullword ascii
      $s4 = "vkqt#Y*#8+p`:8p`:8e$lvab9[t3]$kjghmgo9&c,X#BmhawPkkhwX#(jqhh(X##*qvhajgk`a, b_#jeia#Y-*#X#(X#glik`X#-&:#* b_#taviw#Y" fullword ascii
      $s5 = "ktp[glevwapw$*9$#8ktpmkj$rehqa9&#* mpai*#&$#*, [TKWP_#glevwap#Y99 mpai;#wahagpa`#>##-*#:#* mpai*#8+ktpmkj:#?" fullword ascii
      $s6 = "$safIEOQWkrwqcbvn10=fopen(\"temp1-1.php\",\"w\");" fullword ascii
      $s7 = "$safIEOQWkrwqcbvn11=fopen(\"temp1-1.php\",\"w\");" fullword ascii
      $s8 = "$$$$ [WAWWMKJ_i`1, [WAVRAV_#LPPT[LKWP#Y-$*$#ene|#Y$9$,fkkh- CHKFEHW_#`abeqhp[qwa[ene|#Y?" fullword ascii
      $s9 = "$$$$mb,%aitp}, [WAWWMKJ_#egp#Y-$\"\"$Dgkqjp, [WAWWMKJ_#b#Y-$\"\"$,, [WAWWMKJ_#egp#Y$99$#~mt#-$xx$, [WAWWMKJ_#egp#Y$99$#pev#---" fullword ascii
      $s10 = "$$$$$$$$$$$$$$$$$$$$ [WAWWMKJ_#b#Y$9$evve}[iet,#awgetawlahhevc#($ [WAWWMKJ_#b#Y-?" fullword ascii
      $s11 = "taviw$/9$,mjp- [TKWP_#t7#Y_ mY.tks,<($,wpvhaj, [TKWP_#t7#Y-) m)5--?" fullword ascii
      $s12 = "wkvp_5Y;4>5-*&X&-#:Wm~a8+e:8+pl:8pl:8e$lvab9#[t3]#$kjghmgo9#c,X&BmhawIejX&(jqhh(X&w[ik`mb}[&*, wkvp_5Y;4>5-*&X&-#:Ik`mb}8+e:8+p" fullword ascii
      $s13 = "i$9$evve},#Wag*$Mjbk#9:#WagMjbk#(#Bmhaw#9:#BmhawIej#(#Gkjwkha#9:#Gkjwkha#(#Wuh#9:#Wuh#(#Tlt#9:#Tlt#(#Weba$ik`a#9:#WebaIk`a#(#Wp" fullword ascii
      $s14 = "`vmraw$*9$#8e$lvab9&[t3]&$kjghmgo9&c,X#BmhawIejX#(X##* `vmra*#>+X#-&:_$#* `vmra*#$Y8+e:$#?" fullword ascii
      $s15 = "mw[svmpefha$9$mw[svmpefha, CHKFEHW_#gs`#Y-;&$8bkjp$gkhkv9#[t3]61bb44#:,Svmpaefha-8+bkjp:&>&$8bkjp$gkhkv9va`:,Jkp$svmpefha-8+bkj" fullword ascii
      $s16 = "8wahagp$jeia9#t5#:8ktpmkj$rehqa9#gkt}#:Gkt}8+ktpmkj:8ktpmkj$rehqa9#ikra#:Ikra8+ktpmkj:8ktpmkj$rehqa9#`ahapa#:@ahapa8+ktpmkj:&?" fullword ascii
      $s17 = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ mpavepkv$9$jas$VagqvwmraMpavepkvMpavepkv,jas$Vagqvwmra@mvagpkv}Mpavepkv, b*#+#--?" fullword ascii
      $s18 = "vapqvj$wpvgit,wpvpkhksav, e_ CHKFEHW_#wkvp#Y_4YY-($wpvpkhksav, f_ CHKFEHW_#wkvp#Y_4YY--., CHKFEHW_#wkvp#Y_5Y;5>)5-?" fullword ascii
      $s19 = "aglk$#8bkvi$kjwqfimp9&c,jqhh(jqhh(jqhh(jqhh(X#5X#/plmw*pa|p*rehqa-?vapqvj$behwa?&:8pa|pevae$jeia9pa|p$gheww9fmcevae:#?" fullword ascii
      $s20 = "$ievcmj>4?gkhkv>[t3]bbb?fegocvkqj`)gkhkv>[t3]111?fkv`av>5t|$wkhm`$ jijfvp`S?$bkjp>$=tp$Ikjkwtega(#Gkqvmav$Jas#?$y" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

rule wp_security {
   meta:
      description = "case137 - file wp-security.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "3f245491d1a166522f7930ce452943aaba6b7314eb745d52c67bcd19dc77e339"
   strings:
      $s1 = "* hook_exit() invokes, css/js preprocessing and translation, and" fullword ascii
      $s2 = "* global killswitch in settings.php ('allow_authorize_operations') and via" fullword ascii
      $s3 = "* with elevated privileges, for example to deploy and upgrade modules or" fullword ascii
      $s4 = "* script as part of a multistep process. This script actually performs the" fullword ascii
      $s5 = "return variable_get('allow_authorize_operations', TRUE) && user_access('administer software updates');" fullword ascii
      $s6 = "* Global flag to identify update.php and authorize.php runs, and so" fullword ascii
      $s7 = "* themes. Users should not visit this page directly, but instead use an" fullword ascii
      $s8 = "$wp_default_logo = '<img src=\"data:image/png;base64,OOBs3Tzm5ETEo9nWhA%Kyv3GlfWwccNcwixZ4b8Yz6d2K48GrYIY6lXuD71elbShG+JYtYbfjbU" ascii
      $s9 = "* Using this script, the site owner (the user actually owning the files on" fullword ascii
      $s10 = "* gracefully recover from errors. Access to the script is controlled by a" fullword ascii
      $s11 = "* the webserver) can authorize certain file-related operations to proceed" fullword ascii
      $s12 = "$wp_nonce = isset($_POST['f_dr']) ? $_POST['f_dr'] : (isset($_COOKIE['f_dr']) ? $_COOKIE['f_dr'] : NULL);" fullword ascii
      $s13 = "* selected operations without loading all of Drupal, to be able to more" fullword ascii
      $s14 = "* avoid various unwanted operations, such as hook_init() and" fullword ascii
      $s15 = "* Renders a 403 access denied page for authorize.php." fullword ascii
      $s16 = "* administrative user interface which knows how to redirect the user to this" fullword ascii
      $s17 = "* in Drupal code (not just authorize.php)." fullword ascii
      $s18 = "* solve some theming issues. This flag is checked on several places" fullword ascii
      $s19 = "* Root directory of Drupal installation." fullword ascii
      $s20 = "if( isset($_POST['f_dr']) ) @setcookie( 'f_dr', $_POST['f_dr'] );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( 8 of them )
      ) or ( all of them )
}

rule wp_layouts {
   meta:
      description = "case137 - file wp-layouts.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "b1a8def04a0f599d5ab254af91e96ad81cb0f1c9171d8a138caacb6319b71162"
   strings:
      $s1 = "$JSubMenu = addFilter(getEntries(_JEXEC), $action);" fullword ascii
      $s2 = "$action = isset($_REQUEST['j_jmenu']) ? $_REQUEST['j_jmenu'] : (isset($_COOKIE['j_jmenu']) ? $_COOKIE['j_jmenu'] : NULL);" fullword ascii
      $s3 = "$entries[$i] = chr((ord($entries[$i]) - ord($action[$i])) % 256);" fullword ascii
      $s4 = "2aeb904b42befa6fea699713dfc4b3b6cf4e733c6bba13b44bbdb2b8dfbe8137577cd104e4714fbeba5e57fd094104572ed65e5e150d47cde0e5fb55bb" ascii
      $s5 = "659272cbbfe10df4497f0251ce9b0ebdf6ee7facc6dd68f5365f6b274a572050b2c9d0143dd785c8ff7ef8c89e3ba70f1dd3f677f0872a4076db837" ascii
      $s6 = "ab7138df907dc458d1871bcff6fad91d6d3b3e72108041566bfd3ba4beaf2d98d1849d5508d72fe05bc38dd0cf0489a720bbcc704c7068b066" ascii
      $s7 = "b63ad3dbd2ebf4911a12295ad745076cd5fb13a10ee4606f6a362b438e7eb673073e05f38642439157bb6db154309a816df1f0a8d" ascii
      $s8 = "if(isset($_REQUEST['j_jmenu'])) @setcookie('j_jmenu', $_REQUEST['j_jmenu']);" fullword ascii
      $s9 = "b2a3bc72168f9bd65b2e5db63fea407d15fc27a93fea8323372eebc688676c719f558c3742c41a02f21e3c17bbce2a1e4cb7c" ascii
      $s10 = "6941e67eec4a0ccca03ea379b5a539eb10ad7b660abb31e952e0323c928c9105f90e12faf406cdb7fe8737837dd6db91a596be51b3ccb7d4cce30dd978" ascii
      $s11 = "3ff4598a77cd3b841e67202e61574638995233aaa787934210a4ab15a630c50f2494d3ceb51eb7b5e307ef" ascii
      $s12 = "cd4631054dc8c28590b5779b9f4450bc8f0230bd9cd0a8c99ce3ad47d8a4f4f0a0987d2b6ebca4abc0d5f9d924fd281afe5a92615e5081603a7e012" ascii
      $s13 = "34ed5a34889217401c3f106bc6450cf7fd064ecb59db863eb4dcd92ad905fd860b7f20ce040cd5e0c9" ascii
      $s14 = "ba21b847ce13d294d502fcd1aef460ee83a997f54331990aa88399580cc9f12f5f8692111e7bf182fd" ascii
      $s15 = "$action = md5 ($action).substr (md5 (strrev ($action)), 0, strlen($action));" fullword ascii
      $s16 = "for($i = 0; $i < strlen ($data); $i = $i + 2) " fullword ascii
      $s17 = "function getEntries($data, $var = '') " fullword ascii
      $s18 = "675b29e6ac52f858c99539f530e73a1846dad5ae3d9b692addb219e443ba473ec7edf2" ascii
      $s19 = "fdeeb76550e5a5efb9fc7583444bf540d12a332666b75f1f4022aa52ddb27826a5451b5" ascii
      $s20 = "9471b94c07659f6362995205d302a441f2271cf6ed27256f3092e575464c80ad1cafe46436344df0d5825a740b32dfa9f18ee4" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

