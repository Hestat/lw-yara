/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-25
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_25_18_site_version {
   meta:
      description = "shell2 - file site-version.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "b131f3261fd40891decdcc5df429b2abb50cb12827a94cbaf994e29974affd38"
   strings:
      $s1 = "* Show Site Version Administration Settings" fullword ascii
      $s2 = "/** Show Enrcypted WordPress Version */" fullword ascii
      $s3 = "$p28 = \"\\x70\\x72\\x65\\x67\\x5F\\x72\\x65\\x70\\x6C\\x61\\x63\\x65\";" fullword ascii
      $s4 = "if ($_REQUEST['wp_version_info']) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_09_25_18_Parser {
   meta:
      description = "shell2 - file Parser.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "bc3658527871f653b7034dc05e4e5f5f589723e273da2fc7a9ea6c4045e6dc7f"
   strings:
      $s1 = "* Descriptor" fullword ascii
      $s2 = "* Request Parser Variables" fullword ascii
      $s3 = "* Show Parser UTF-8 Chars" fullword ascii
      $s4 = "$p28 = \"\\x70\\x72\\x65\\x67\\x5F\\x72\\x65\\x70\\x6C\\x61\\x63\\x65\";" fullword ascii
      $s5 = "* Router" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 40KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_09_25_18_webr00tv3 {
   meta:
      description = "shell2 - file webr00tv3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "c9c6155d2f88fe2e651768dd1f5dc69fb8470c612dd46488d2b475a004036026"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "SUlsSUk9J2ZpbGUnOyRJSUlJSUlJSUlJMUk9J3N5bWxpbmsnOyRJSUlJSUlJSUlJbDE9J2Z3cml0ZSc7JElJSUlJSUlJSUlsbD0nZm9wZW4nOyRJSUlJSUlJSUlJSWw9" ascii /* base64 encoded string 'IIlII='file';$IIIIIIIIII1I='symlink';$IIIIIIIIIIl1='fwrite';$IIIIIIIIIIll='fopen';$IIIIIIIIIIIl=' */
      $s3 = "SUlJSWwxSTFJPSdoaWdobGlnaHRfZmlsZSc7JElJSUlJSUlsMUlsMT0nc2hvd19zb3VyY2UnOyRJSUlJSUlJbDFJbGw9J2h0bWxlbnRpdGllcyc7JElJSUlJSUlsMUls" ascii /* base64 encoded string 'IIIIl1I1I='highlight_file';$IIIIIIIl1Il1='show_source';$IIIIIIIl1Ill='htmlentities';$IIIIIIIl1Il' */
      $s4 = "bGxsSUk9J2h0bWxzcGVjaWFsY2hhcnMnOyRJSUlJSUlJbGxJSTE9J2NobW9kJzskSUlJSUlJSWxsSUlsPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSWxJMTFJPSdmY2xv" ascii /* base64 encoded string 'lllII='htmlspecialchars';$IIIIIIIllII1='chmod';$IIIIIIIllIIl='base64_decode';$IIIIIIIlI11I='fclo' */
      $s5 = "ST0nZnJlYWQnOyRJSUlJSUlJbGwxbGw9J3N0cmlwY3NsYXNoZXMnOyRJSUlJSUlJbGwxSTE9J2ZpbGVzaXplJzskSUlJSUlJSWxsMUlJPSd1bmxpbmsnOyRJSUlJSUlJ" ascii /* base64 encoded string 'I='fread';$IIIIIIIll1ll='stripcslashes';$IIIIIIIll1I1='filesize';$IIIIIIIll1II='unlink';$IIIIIII' */
      $s6 = "tUHBRcVNzVnZYeFp6MDEyMzQ1Njc4OSsvPScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk" ascii /* base64 encoded string 'PpQqSsVvXxZz0123456789+/=','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'))' */
      $s7 = "c2VyX2Fib3J0JzskSUlJSUlJSTFJbEkxPSdpc19maWxlJzskSUlJSUlJSTFJSTFsPSdteXNxbF9xdWVyeSc7JElJSUlJSUkxSUlsMT0nbXlzcWxfY29ubmVjdCc7JElJ" ascii /* base64 encoded string 'ser_abort';$IIIIIII1IlI1='is_file';$IIIIIII1II1l='mysql_query';$IIIIIII1IIl1='mysql_connect';$II' */
      $s8 = "ZXhlYyc7JElJSUlJSUlsSUlsST0nY3VybF9zZXRvcHQnOyRJSUlJSUlJbElJSTE9J2N1cmxfaW5pdCc7JElJSUlJSUlJMTExST0nc3ByaW50Zic7JElJSUlJSUlJMWxs" ascii /* base64 encoded string 'exec';$IIIIIIIlIIlI='curl_setopt';$IIIIIIIlIII1='curl_init';$IIIIIIII111I='sprintf';$IIIIIIII1ll' */
      $s9 = "MUlJbD0ncGNsb3NlJzskSUlJSUlJSTExSUlJPSdmZ2V0cyc7JElJSUlJSUkxbDExbD0nZmVvZic7JElJSUlJSUkxbDExST0ncG9wZW4nOyRJSUlJSUlJMWwxSUk9J3Jv" ascii /* base64 encoded string '1IIl='pclose';$IIIIIII11III='fgets';$IIIIIII1l11l='feof';$IIIIIII1l11I='popen';$IIIIIII1l1II='ro' */
      $s10 = "bGxsMTE9J3JtZGlyJzskSUlJSUlJSWxsbDFsPSdjb3VudCc7JElJSUlJSUlsbGxsMT0nZXhwbG9kZSc7JElJSUlJSUlsbGxJbD0naXNfd3JpdGFibGUnOyRJSUlJSUlJ" ascii /* base64 encoded string 'lll11='rmdir';$IIIIIIIlll1l='count';$IIIIIIIllll1='explode';$IIIIIIIlllIl='is_writable';$IIIIIII' */
      $s11 = "dW5kJzskSUlJSUlJSTFsbDFJPSdmc29ja29wZW4nOyRJSUlJSUlJMWxsbDE9J3JhbmQnOyRJSUlJSUlJMWxJMTE9J3RpbWUnOyRJSUlJSUlJMWxJbDE9J2lnbm9yZV91" ascii /* base64 encoded string 'und';$IIIIIII1ll1I='fsockopen';$IIIIIII1lll1='rand';$IIIIIII1lI11='time';$IIIIIII1lIl1='ignore_u' */
      $s12 = "XHr8Xk10Pk1nuBmcJdlymBTw5F2wzUTlDH0pSBlF0h1f5foOkWzavcrfoDlLZampjGAkBC0f4fllbABfUa1kXCLfUFrleYeiHHlp2CM5Oh1nyUlYWcz09kZL7tm0hcBx" ascii
      $s13 = "wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdFbnRlcnlvdXdraFJIWUtOV09VVEFhQmJDY0RkRmZHZ0lpSmpMbE1" ascii /* base64 encoded string '0O0=$OOO0000O0($OOO00000O($O0O00OO00($O000O0O00,0x17c),'EnteryouwkhRHYKNWOUTAaBbCcDdFfGgIiJjLlM' */
      $s14 = "ST0nb3JkJzskSUlJSUlJSUkxSUkxPSdzdHJwb3MnOyRJSUlJSUlJSUkxSUk9J2ZpbGVvd25lcic7JElJSUlJSUlJSWwxMT0ncG9zaXhfZ2V0cHd1aWQnOyRJSUlJSUlJ" ascii /* base64 encoded string 'I='ord';$IIIIIIII1II1='strpos';$IIIIIIIII1II='fileowner';$IIIIIIIIIl11='posix_getpwuid';$IIIIIII' */
      $s15 = "yceOlazy5T1OBByOVFyiJBrP0C25DAacwOllBO3OQTliDGaCZHB9AaLczCznaYypocrxUOMOZCM1Da1pBFyfjHeaDCznyf1aQAmpJalpXT1OBDlcQBbiLaMIza1amHBO" ascii
      $s16 = "SUlJSUlsMTExbD0nZXJlZyc7JElJSUlJSUlsMWwxMT0ncHJlZ19tYXRjaCc7JElJSUlJSUlsMWwxbD0naXNfZGlyJzskSUlJSUlJSWwxbGxsPSdpbmlfZ2V0JzskSUlJ" ascii /* base64 encoded string 'IIIIIl111l='ereg';$IIIIIIIl1l11='preg_match';$IIIIIIIl1l1l='is_dir';$IIIIIIIl1lll='ini_get';$III' */
      $s17 = "SUlJSTExbDFsPSdjb3B5JzskSUlJSUlJSTExbEkxPSd1cmxlbmNvZGUnOyRJSUlJSUlJMTFJMWw9J2hlYWRlcic7JElJSUlJSUkxMUkxST0nZXhlYyc7JElJSUlJSUkx" ascii /* base64 encoded string 'IIII11l1l='copy';$IIIIIII11lI1='urlencode';$IIIIIII11I1l='header';$IIIIIII11I1I='exec';$IIIIIII1' */
      $s18 = "SUlsMUk9J3RyaW0nOyRJSUlJSUlJSUlsbDE9J2ZsdXNoJzskSUlJSUlJSUlJbGxJPSdwcmVnX21hdGNoX2FsbCc7JElJSUlJSUlJSWxJMT0nZXJlZ2knOyRJSUlJSUlJ" ascii /* base64 encoded string 'IIl1I='trim';$IIIIIIIIIll1='flush';$IIIIIIIIIllI='preg_match_all';$IIIIIIIIIlI1='eregi';$IIIIIII' */
      $s19 = "c2UnOyRJSUlJSUlJbEkxSWw9J2NoZGlyJzskSUlJSUlJSWxJbGxsPSdzdWJzdHInOyRJSUlJSUlJbElJMUk9J2N1cmxfY2xvc2UnOyRJSUlJSUlJbElJbDE9J2N1cmxf" ascii /* base64 encoded string 'se';$IIIIIIIlI1Il='chdir';$IIIIIIIlIlll='substr';$IIIIIIIlII1I='curl_close';$IIIIIIIlIIl1='curl_' */
      $s20 = "uGoicHlavUBx3dLlpf2lhGAlzULfSfapuajORauYRULfKGBaCWjnkW0r5UAYhY1ieAjfDBypPtMkeDolcBr5STMpUclpuaMpJHlkSU0c3dLlQF0shO055caitHrleYel" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

