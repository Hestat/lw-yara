/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_107_175_218_241_2018_10_14a_shells_dc3 {
   meta:
      description = "shells - file dc3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "3ace35f15c854f5e0183a17a38b7e6cafa2553a10c9e3b3fc5f7c06c2ef0f81e"
   strings:
      $x1 = "(){if(empty($_POST[\"ch\"]))$_POST[\"ch\"]=$GLOBALS[\"default\\137charset\"];global $_vza;echo\"<\\150tml><head><met\\x61 http-" ascii
      $s2 = "();}function acTiOnLogout(){SetCoOkIe($GLOBALS[\"coo\\153\"],\"\",TiME()-(int)round(1800+1800));die(\"bye!\");}function _" fullword ascii
      $s3 = "='Content-\\124ype' conte\\156t='\\164ext/h\\x74ml; c\\150\\141rset=\".$_POST[\"\\x63h\"].\"'><t\\151tle>\".$_SERVER[\"HTTP_HOST" ascii
      $s4 = "($_POST[\"p\"]).\" <span>\\117wner\\x2fGroup:</span>\\x20\".$_mkds[\"name\"].\"/\".$_ltxp[\"n\\141me\"].\"<br>\";echo\"<span>Cha" ascii
      $s5 = "lEmtIMe($_POST[\"p\"])).\"\\x22\\076<in\\160ut type=submi\\164 value=\\042>>\\042></f\\157r\\155>\";break;}echo\"</div>\";_" fullword ascii
      $s6 = "();}function ActiOnFt(){if(isset($_POST[\"p\"]))$_POST[\"p\"]=StR_rOT13(uRLdeCODE($_POST[\"p\"]));if(isset($_POST[\"x\"])){switc" ascii
      $s7 = "($_xw[\"size\"]):$_xw[\"type\"]).\"<\\x2ftd><td>\".$_xw[\"modify\"].\"</td><td>\".$_xw[\"owner\"].\"/\".$_xw[\"gr\\x6fup\"].\"</" ascii
      $s8 = "s\"],\"po\\163ix\\x5fgetgrgid\")===false)){function PoSIx_gETgRGid($_hp){return false;}}function _" fullword ascii
      $s9 = "66666666666667" ascii /* hex encoded string 'ffffffg' */
      $s10 = "666666666667" ascii /* hex encoded string 'fffffg' */
      $s11 = "6666666667" ascii /* hex encoded string 'ffffg' */
      $s12 = "$ps=\"de9\\x31\\070f6ea2e947\\x39ed9d81a814\\067\\144bae3d\";$_vza=\"#df5\";$_smp=\"fm\";$default_charset=\"Windows-1\\06251\";i" ascii
      $s13 = "($_ioko){if(fUnCTIOn_ExiSts(\"scandi\\x72\")){return scAnDir($_ioko);}else{$_ip=opeNdIr($_ioko);while(false!==($_io=rEadDir($_ip" ascii
      $s14 = "ed\");else echo\"unlink error\\x21\";if($_POST[\"p\"]!=\"yes\")_" fullword ascii
      $s15 = "(FIlESizE($_POST[\"p\"])):\"-\").\"\\040<\\163\\160an>\\x50ermi\\163sion:<\\057span>\\040\"._" fullword ascii
      $s16 = "\\x2f\\x61\\x3e <span>Dat\\145ti\\x6de:</span> \".daTE(\"Y-m-d H:i:s\").\"<br\\x3e\".($_jl?_" fullword ascii
      $s17 = "($_xw);else @Unlink($_xw);}break;}if($_rdbd)ToUCh($_POST[\"c\"],$_rdbd,$_rdbd);}_" fullword ascii
      $s18 = "7=3 \\x63ellsp\\141cing=0 width=100%><tr>\".$_ubi.\"</tr><\\x2ft\\141ble><\\x64iv style=\\x22margin:5\\042>\";}function _" fullword ascii
      $s19 = "(isset($_POST[\"c\"])?$_POST[\"c\"]:$GLOBALS[\"c\\167d\"]);if($_zka===false){echo\"Can't \\157pen this\\040folder!\";_" fullword ascii
      $s20 = "d(0+0+0),-154+157);if(isset($_POST[\"ps\"])&&(md5($_POST[\"ps\"])==$ps))_" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_107_175_218_241_2018_10_14a_shells_dropper {
   meta:
      description = "shells - file dropper.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "926034e2fbffb5bbf065c983bb74020fed3db9a8b0c55860df066385a7c0af2b"
   strings:
      $s1 = "MRVNbJ2ZpbGUnXVsnbmFtZSddKSkgeyBlY2hvICc8Yj5VcGxvYWQgQ29tcGxhdGUgISEhPC9iPjxicj4nOyB9IGVjaG8gJzxmb3JtIGFjdGlvbj0iIiBtZXRob2Q9InB" ascii /* base64 encoded string 'ES['file']['name'])) { echo '<b>Upload Complate !!!</b><br>'; } echo '<form action="" method="p' */
      $s2 = "vc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPjxpbnB1dCB0eXBlPSJmaWxlIiBuYW1lPSJmaWxlIiBzaXplPSI1MCI+PGlucHV0IHR5cGU9InN1Ym1pdCI" ascii /* base64 encoded string 'st" enctype="multipart/form-data"><input type="file" name="file" size="50"><input type="submit"' */
      $s3 = "file_put_contents($fileName, base64_decode($fileData));" fullword ascii
      $s4 = "$fileName = 'sessions.php';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_107_175_218_241_2018_10_14a_shells_wso {
   meta:
      description = "shells - file wso.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "0238dd8da8ae85deb84fe18d1fa5df6673f500554fd4a83bd48d6633f600e8d3"
   strings:
      $s1 = "$cook = suBstR(Md5($_SERVER[\"HTTP_HOST\"]), (int) round(0 + 0 + 0), -154 + 157);" fullword ascii
      $s2 = "for ($_wvlc = StRLEn($_POST[\"s\"]) - (int) round(0.5 + 0.5); $_wvlc >= (int) round(0 + 0); --$_wvlc) {" fullword ascii
      $s3 = "$_dghz += (int) $_POST[\"s\"][$_wvlc] * poW(-5 - -13, StrLEn($_POST[\"s\"]) - $_wvlc - (-37 + 38));" fullword ascii
      $s4 = "echo \"<script>s_=\\\"\\\";</script><form onsubmit=\\\"g(null,null,'\" . uRLeNCOde(STR_roT13($_POST[\"p\"])) . \"',null,this.to" fullword ascii
      $s5 = "echo \"<script>s_=\\\"\\\";</script><form onsubmit=\\\"g(null,null,'\" . urlENCoDE(stR_Rot13($_POST[\"p\"])) . \"',null,this.ch" fullword ascii
      $s6 = "die(\"<form method=post><input type=password name=ps><input type=submit value='>>'></form>\");" fullword ascii
      $s7 = "return strCMP(strtOlOweR($_av[$GLOBALS[\"sort\"][266 - -235 + -501]]), sTRtOLOWer($_wr[$GLOBALS[\"sort\"][-376 + 376]])) * (" fullword ascii
      $s8 = "echo \"<form onsubmit=\\\"g(null,null,'\" . UrlENCoDE(sTR_Rot13($_POST[\"p\"])) . \"',null,rot13(this.name.value));return f" fullword ascii
      $s9 = "echo \"<form onsubmit=\\\"g(null,null,'\" . UrLenCoDE(sTr_Rot13($_POST[\"p\"])) . \"',null,'1'+utoa(this.text.value));retur" fullword ascii
      $s10 = "if (@Preg_mATcH(\"/\" . join(\"|\", $_wejg) . \"/i\", $_SERVER[\"HTTP_USER_AGENT\"])) {" fullword ascii
      $s11 = "} elseif (($_hp & 8257 - 8400 - -8335) == (int) round(2730.6666666667 + 2730.6666666667 + 2730.6666666667)) {" fullword ascii
      $s12 = "$_wvlc .= $_hp & (int) round(4 + 4) ? $_hp & 1318 + -294 ? \"s\" : \"x\" : ($_hp & 1019 + 5 ? \"S\" : \"-\");" fullword ascii
      $s13 = "if ($cwd[stRLeN($cwd) - (int) round(0.33333333333333 + 0.33333333333333 + 0.33333333333333)] != \"/\") {" fullword ascii
      $s14 = "echo \"<html><head><meta http-equiv='Content-Type' content='text/html; charset=\" . $_POST[\"ch\"] . \"'><title>\" . $_SERVER[\"" ascii
      $s15 = "echo hTMLspECiaLcHARs(@fGeTS($_tdtc, 487 - 872 - -1409));" fullword ascii
      $s16 = "HEADer(\"Content-Disposition: attachment; filename=\" . BAsEnAme($_POST[\"p\"]));" fullword ascii
      $s17 = "die(\"<script>g(null,null,\\\"\" . UrLenCODe($_POST[\"s\"]) . \"\\\",null,\\\"\\\")</script>\");" fullword ascii
      $s18 = "echo HtmLsPeCIAlcHArS(@fgETS($_tdtc, 1218 + -194));" fullword ascii
      $s19 = "if (FunctioN_EXisTs(\"get_magic_quotes_gpc\") && FUncTion_ExISTs(\"array_map\") && FunctION_EXIsTs(\"stripslashes\")) {" fullword ascii
      $s20 = "if (!funCTIon_existS(\"posix_getpwuid\") && sTrPOS($GLOBALS[\"disable_functions\"], \"posix_getpwuid\") === false) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 90KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_107_175_218_241_2018_10_14a_shells_dc2 {
   meta:
      description = "shells - file dc2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "07f20c09a3b101ef7523ea996e2eb3f3e28d022dc8e966e497a3fb3efc22e302"
   strings:
      $s1 = "en0afpiOQ52UuurOpovfl7pj4pLK4k4IjCNghCQunCTLRY3u1DqzA3Ga0uYbgBQ9DPnYQEXecIGcObYp" fullword ascii
      $s2 = "tDEU6AwuJgUL+QanaAbcqH8JT2i9TxDPBLh9mgjMSk/YAqRW9qHi9jndQUwlnpTIRcVrHPzAyQqm5Zfg" fullword ascii
      $s3 = "$s6353 = $wxsE7559($AE1718(\"pX1Nb+PK0t5f4XDmHknXkizq05YsjT22PKMc2/IryXfOeceGQJGUxGOJ5CUpW3N8DWSTRTYBkkUQIPsA" fullword ascii
      $s4 = "5oonn/8pCmR36EYEKYXD6clqxbeATVH/9UriH/75vw==\")); print ($s6353);" fullword ascii
      $s5 = "$AE1718 = chr(98).\"a\".chr(115).\"\".chr(101).\"\\x364_d\\x65c\\x6F\\x64\".chr(101);" fullword ascii
      $s6 = "pXkzJiiBf7DZ0KBFmOHiFP89v7oGjvYDsH8VnszIKEYxHDPwH9OPAT9F74g2tAoj2M2RtWWDCcS6aOuz" fullword ascii
      $s7 = "92ZD26sf1ivNvRJ9rDQw+xzuYBdajLhsnxCCJuigsse/GdI3vkTAVt+GRMx9UN/j3zuQtMphtVpuyv9a" fullword ascii
      $s8 = "L3/r4gkOkGeCmdmIKPrh05GyKxxbr6SD0P/v0V10ElgchjXC+HBZzsv1sscjcsLpkuudgcPxeLQfn3YQ" fullword ascii
      $s9 = "<?php $wxsE7559 = chr(103).\"\\x7a\\x69\\x6e\\x66\".chr(108).\"\\x61te\";" fullword ascii
      $s10 = "2HRCrlJTkc6w8YhKYpA9sYbgC4Xs4wyEB8tXBtdCCgDbWAJHiRXi7/Tk7HZbr48wzRAJEYeSYVAnIWXR" fullword ascii
      $s11 = "sMQ//Jf/8N9FWsUTJ2Tkx5vZeOJzUfG1/Akc9t1XsfMx1m38EqkLgh/6kh+QpSG4ARP/565vnZgcSGYu" fullword ascii
      $s12 = "lU9tux3w1MwQH7B4jsl4m/6T//Vf+akg+ELCPEd0qfEaFcnsjBr5j1GjPHy+KEC0nmC9F6IIJfso+GOe" fullword ascii
      $s13 = "JiSdqve//+W/+m957Dpo+djB9LNvT/QPq356BcInaTJLKaxfpNLIsdaABdXLU7PQIkpg3gqR3mhTfalz" fullword ascii
      $s14 = "Ja2EI6nFO/vQiuHPB6v+tTW6/AZ8JUYXYKJDGjBM31bJatpB9Lo/ugzSgNigCrPus3//z6iG7d67IjHj" fullword ascii
      $s15 = "iI8iPPFHBoInzFX+gx70r07WFjdEZ+WyijPLMxrAlb7uJ+XEpDhVZjsbi/r/83LZpRnpYwMk6gjTGOWk" fullword ascii
      $s16 = "0/XJxPiUV/fV8m+u7eTVv6hF0W2hrO7beElheKtVK7tIfuqfnPX9PH2+3Tbq17fb6lwrV5R6pa5cueFt" fullword ascii
      $s17 = "r/RTVNs2DFmNa2CQePpCK+zCuuLnQim9mMq1zH97PywoYIS3lUZLjLLcpd46iYT4n//0X+R5PiKNKwmz" fullword ascii
      $s18 = "AEmSHWEc8l3bZCu2fyBKiT0mwwyXBXFKBfMoM9ZkuDn9HiMLbjrX+WSFTE5SuGzCfmhjScJN3qUjyj/o" fullword ascii
      $s19 = "g/HUHIzyoqCstjliR/QWPYBLK636y8FAzsjx0DtmJZ+br2kEKhmO4P4Q3C96Iaj7bPLBIdn8Al+z7A0W" fullword ascii
      $s20 = "M/4h5bE7K7xfY4iYFAPb1bqkXzREMrQ1jNLBrqvZyFhjafBMQGzRduedpqiapiGwTnfwVYFnl8moJROk" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( 8 of them )
      ) or ( all of them )
}
