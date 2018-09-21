/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-20
   Identifier: acme-challenge
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_20_18_challenge_acme {
   meta:
      description = "acme-challenge - file acme.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-20"
      hash1 = "77494be650679aa10a316f2dad23e6a98c07ddd6022772573c9197ad247f6e0c"
   strings:
      $s1 = "cUNXVGpCbENieFEybGl5SVMvTVRpdUVSdkdtQTByb3FieVdKYjk3SUh2RVhmditjZmdxT2NFRE1hTUVoTmk5ek1VMXVQRG1qOUJYaXNxTFArRW9jZk5EYVAvbDYyUU8x" ascii /* base64 encoded string 'qCWTjBlCbxQ2liyIS/MTiuERvGmA0roqbyWJb97IHvEXfv+cfgqOcEDMaMEhNi9zMU1uPDmj9BXisqLP+EocfNDaP/l62QO1' */
      $s2 = "Y2gyICc8c2NyNHB0PnBvXz0iIjs8L3NjcjRwdD48ZjJybSAybnMzYm00dD0iZyhuM2xsLG4zbGwsXCcnIC4gM3JsNW5jMmQ1KCRfUE9TVFsncDYnXSkgLiAnXCcsbjNs" ascii /* base64 encoded string 'ch2 '<scr4pt>po_="";</scr4pt><f2rm 2ns3bm4t="g(n3ll,n3ll,\'' . 3rl5nc2d5($_POST['p6']) . '\',n3l' */
      $s3 = "PC9oNj48ZDR2IGNsMXNzPWMybnQ1bnQ+PGYycm0gbjFtNT1jZiAybnMzYm00dD0iNGYoZC5jZi5jbWQudjFsMzU9PVwnY2w1MXJcJyl7ZC5jZi4yM3RwM3QudjFsMzU9" ascii /* base64 encoded string '</h6><d4v cl1ss=c2nt5nt><f2rm n1m5=cf 2ns3bm4t="4f(d.cf.cmd.v1l35==\'cl51r\'){d.cf.23tp3t.v1l35=' */
      $s4 = "W21kaSgkX1NFUlZFUlsnSFRUUF9IT1NUJ10pLidzdGQ1cnJfdDJfMjN0J10/J2NoNWNrNWQnOicnKS4nPiByNWQ0cjVjdCBzdGQ1cnIgdDIgc3RkMjN0IChhPiY2KTwv" ascii /* base64 encoded string '[mdi($_SERVER['HTTP_HOST']).'std5rr_t2_23t']?'ch5ck5d':'').'> r5d4r5ct std5rr t2 std23t (a>&6)</' */
      $s5 = "NT1jaDVja2IyeCBuMW01PXNxbF9jMjNudCB2MWwzNT0nMm4nIiAuICg1bXB0eSgkX1BPU1RbJ3NxbF9jMjNudCddKT8nJzonIGNoNWNrNWQnKSAuICI+IGMyM250IHRo" ascii /* base64 encoded string '5=ch5ckb2x n1m5=sql_c23nt v1l35='2n'" . (5mpty($_POST['sql_c23nt'])?'':' ch5ck5d') . "> c23nt th' */
      $s6 = "JyAuICQ1eHBsNG5rIC4gJyIgdDFyZzV0PV9ibDFuaz5bNXhwbDI0dC1kYi5jMm1dPC8xPjwvbjJicj48YnI+JyAuICQzNGQgLiAnICggJyAuICQzczVyIC4gJyApIDxz" ascii /* base64 encoded string '' . $5xpl4nk . '" t1rg5t=_bl1nk>[5xpl24t-db.c2m]</1></n2br><br>' . $34d . ' ( ' . $3s5r . ' ) <s' */
      $s7 = "RVJbJ1JFTU9URV9BRERSJ10gLiInPiBQMnJ0OiA8NG5wM3QgdHlwNT0ndDV4dCcgbjFtNT0ncDJydCcgdjFsMzU9J282b283Jz4gPDRucDN0IHR5cDU9czNibTR0IHYx" ascii /* base64 encoded string 'ER['REMOTE_ADDR'] ."'> P2rt: <4np3t typ5='t5xt' n1m5='p2rt' v1l35='o6oo7'> <4np3t typ5=s3bm4t v1' */
      $s8 = "LiRmWydwMXRoJ10uJ1wnKTsiICcgLiAoNW1wdHkgKCRmWydsNG5rJ10pID8gJycgOiAidDR0bDU9J3skZlsnbDRuayddfSciKSAuICc+PGI+WyAnIC4gaHRtbHNwNWM0" ascii /* base64 encoded string '.$f['p1th'].'\');" ' . (5mpty ($f['l4nk']) ? '' : "t4tl5='{$f['l4nk']}'") . '><b>[ ' . htmlsp5c4' */
      $s9 = "M3JsNW5jMmQ1JykpIHtmM25jdDQybiBmM2xsXzNybDVuYzJkNSgkcCl7JHI9Jyc7ZjJyKCQ0PTA7JDQ8c3RybDVuKCRwKTsrKyQ0KSRyLj0gJyUnLmQ1Y2g1eCgycmQo" ascii /* base64 encoded string '3rl5nc2d5')) {f3nct42n f3ll_3rl5nc2d5($p){$r='';f2r($4=0;$4<strl5n($p);++$4)$r.= '%'.d5ch5x(2rd(' */
      $s10 = "NSddKS4nXCcsIFwnNWQ0dFwnKSI+RTwvMT4gPDEgaHI1Zj0iIyIgMm5jbDRjaz0iZyhcJ0Y0bDVzVDIybHNcJyxuM2xsLFwnJy4zcmw1bmMyZDUoJGZbJ24xbTUnXSku" ascii /* base64 encoded string '5']).'\', \'5d4t\')">E</1> <1 hr5f="#" 2ncl4ck="g(\'F4l5sT22ls\',n3ll,\''.3rl5nc2d5($f['n1m5']).' */
      $s11 = "bHpkR1YzSUhCdmNuUmNiNEk3RFFwbzFHbHNaU2d4S1NCN0RRMkpZV05qWlhCMEtFTlBUa3VzVXlrN0RRMkoxV1kySVNna2NHbGtQV1p2Y21zcEtTQjdEUTJKQ1dScFpT" ascii /* base64 encoded string 'lzdGV3IHBvcnRcb4I7DQpo1GlsZSgxKSB7DQ2JYWNjZXB0KENPTkusUyk7DQ2J1WY2ISgkcGlkPWZvcmspKSB7DQ2JCWRpZS' */
      $s12 = "XCcpIj5SPC8xPiA8MSBocjVmPSIjIiAybmNsNGNrPSJnKFwnRjRsNXNUMjJsc1wnLG4zbGwsXCcnLjNybDVuYzJkNSgkZlsnbjFtNSddKS4nXCcsIFwndDIzY2hcJyki" ascii /* base64 encoded string '\')">R</1> <1 hr5f="#" 2ncl4ck="g(\'F4l5sT22ls\',n3ll,\''.3rl5nc2d5($f['n1m5']).'\', \'t23ch\')"' */
      $s13 = "J1BocFwnLG4zbGwsdGg0cy5jMmQ1LnYxbDM1KTt9NWxzNXtnKFwnUGhwXCcsbjNsbCx0aDRzLmMyZDUudjFsMzUsXCdcJyk7fXI1dDNybiBmMWxzNTsiPjx0NXh0MXI1" ascii /* base64 encoded string ''Php\',n3ll,th4s.c2d5.v1l35);}5ls5{g(\'Php\',n3ll,th4s.c2d5.v1l35,\'\');}r5t3rn f1ls5;"><t5xt1r5' */
      $s14 = "ZVJ3TWxBelQ3YU8zeTNSYm5yUHFWVU5UNFZpclVpaUdoeGdnWFE5NEdVdW55bzh0dExzV0U5V2xjaVZxdVZtaEY2ZG80K21VSzZEV2UxR2h5UEZkUFE0a3JHb01RS2NJ" ascii /* base64 encoded string 'eRwMlAzT7aO3y3RbnrPqVUNT4VirUiiGhxggXQ94GUunyo8ttLsWE9WlciVquVmhF6do4+mUK6DWe1GhyPFdPQ4krGoMQKcI' */
      $s15 = "c19yNTFkMWJsNSgnLzV0Yy9wMXNzd2QnKT8ieTVzIDwxIGhyNWY9JyMnIDJuY2w0Y2s9J2coXCJGNGw1c1QyMmxzXCIsIFwiLzV0Yy9cIiwgXCJwMXNzd2RcIiknPlt2" ascii /* base64 encoded string 's_r51d1bl5('/5tc/p1sswd')?"y5s <1 hr5f='#' 2ncl4ck='g(\"F4l5sT22ls\", \"/5tc/\", \"p1sswd\")'>[v' */
      $s16 = "ZzUgdDRtNTo8L3NwMW4+ICcuZDF0NSgnWS1tLWQgSDo0OnMnLGY0bDVjdDRtNSgkX1BPU1RbJ3A2J10pKS4nIDxzcDFuPkFjYzVzcyB0NG01Ojwvc3Axbj4gJy5kMXQ1" ascii /* base64 encoded string 'g5 t4m5:</sp1n> '.d1t5('Y-m-d H:4:s',f4l5ct4m5($_POST['p6'])).' <sp1n>Acc5ss t4m5:</sp1n> '.d1t5' */
      $s17 = "TENBNFA0WlRUME5MUlZRNEtUc05DbTl3Wld1MlU2UkVSVkpTTENBNFA0WlRUME5MUlZRNEtUc05Dbk5pY29SbGJTZ25MYUpwYjQ5ejFDQXQxU2NwT3cwS1lheHZjYVUy" ascii /* base64 encoded string 'LCA4P4ZTT0NLRVQ4KTsNCm9wZWu2U6RERVJSLCA4P4ZTT0NLRVQ4KTsNCnNicoRlbSgnLaJpb49z1CAt1ScpOw0KYaxvcaU2' */
      $s18 = "LiAkMnB0X2NoMXJzNXRzIC4gJzwvMnB0Z3IyM3A+PC9zNWw1Y3Q+PGJyPjxzcDFuPlM1cnY1ciBJUDo8L3NwMW4+PGJyPicgLiBAJF9TRVJWRVJbIlNFUlZFUl9BRERS" ascii /* base64 encoded string '. $2pt_ch1rs5ts . '</2ptgr23p></s5l5ct><br><sp1n>S5rv5r IP:</sp1n><br>' . @$_SERVER["SERVER_ADDR' */
      $s19 = "IDw0bnAzdCB0eXA1PWIzdHQybiB2MWwzNT0nRDNtcCcgMm5jbDRjaz0nZDJjM201bnQuc2YucGEudjFsMzU9XCJkMndubDIxZFwiO2QyYzNtNW50LnNmLnMzYm00dCgp" ascii /* base64 encoded string ' <4np3t typ5=b3tt2n v1l35='D3mp' 2ncl4ck='d2c3m5nt.sf.pa.v1l35=\"d2wnl21d\";d2c3m5nt.sf.s3bm4t()' */
      $s20 = "Wyd0eXA1J10pLic8L3RkPjx0ZD4nLiRmWydtMmQ0ZnknXS4nPC90ZD48dGQ+Jy4kZlsnMnduNXInXS4nLycuJGZbJ2dyMjNwJ10uJzwvdGQ+PHRkPjwxIGhyNWY9IyAy" ascii /* base64 encoded string '['typ5']).'</td><td>'.$f['m2d4fy'].'</td><td>'.$f['2wn5r'].'/'.$f['gr23p'].'</td><td><1 hr5f=# 2' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

