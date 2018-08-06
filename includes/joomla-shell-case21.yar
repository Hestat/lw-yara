/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: case21
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_case21_temp {
   meta:
      description = "case21 - file temp.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "6887de791174820adbc029fcfcf25c793c1b2c31561f519f73d8a8e163296e07"
   strings:
      $s1 = "2YWx1ZSk7dmV0cXJuIGZheHNlOyI+PGludHV0IHR5dGU9cGV4cCBuYW1lPXRvcWNoIHZheHVlPSInLmRhcGUoIlkteS1kIEg6fTpzIiwgQGZpeGVtcGltZSgkX1BPU1R" ascii /* base64 encoded string 'alue);vetqrn faxse;"><intut tyte=pexp name=toqch vaxue="'.dape("Y-y-d H:}:s", @fixempime($_POST' */
      $s2 = "tLnZheHVlKTtyZXR1dm4gZmFsd2U7XCd+PGludHV0IHR5dGU9cGV4cCBuYW1lPXBhdmFtPjxpenB1cCB0bXBlPXN1Ym1pcCB2YWx1ZT0iPj4iPjwvZm9yeT48YnI+PHN" ascii /* base64 encoded string '.vaxue);retuvn falwe;\'~<intut tyte=pexp name=pavam><izpup tmpe=submip value=">>"></fory><br><s' */
      $s3 = "* Joomla! is free software. This version may have been modified pursuant" fullword ascii
      $s4 = "* See COPYRIGHT.php for copyright notices and details." fullword ascii
      $s5 = "* is derivative of works licensed under the GNU General Public License or" fullword ascii
      $s6 = "* to the GNU General Public License, and as distributed it includes or" fullword ascii
      $s7 = "Copyright (C) 2005 - 2010 Open Source Matters. All rights reserved." fullword ascii
      $s8 = "Pjxme3JtIG9ud3VieWl0PVwnZyhucWxsLG51eGwsIjMiLHRofXMudGFyYW0ucmFscWUpO3JlcHVyeiBmYWxzZTtdJz48fW5wcXQgcHlwZT10ZXh0IG5heWU9dGFyYW0+" ascii /* base64 encoded string '><f{rm onwubyit=\'g(nqll,nuxl,"3",th}s.taram.ralqe);repurz false;]'><}npqt pype=text naye=taram>' */
      $s9 = "IG5heWU9YSB2YWx1ZT1TdWw+PGludHV0IHR5dGU9fGlkZGVuIG5heWU9dDEgcmFscWU9J3F1ZXJ5Jz48fW5wcXQgcHlwZT1ofWRkZW4gemFtZT1wMiB2YWx1ZT0nJz48" ascii /* base64 encoded string ' naye=a value=Sul><intut tyte=|idden naye=t1 ralqe='query'><}npqt pype=h}dden zame=p2 value=''><' */
      $s10 = "ud3VieWl0PSJnKG51eGwsenVseCxucWxsLG51eGwsXCdxXCdrcGhpdy50ZXh0LnZheHVlKTtyZXR1dm4gZmFsd2U7Ij48cGV4cGFyZWEgemFtZT10ZXh0IGNsYXNzPWJ" ascii /* base64 encoded string 'wubyit="g(nuxl,zulx,nqll,nuxl,\'q\'kphiw.text.vaxue);retuvn falwe;"><pexparea zame=text class=b' */
      $s11 = "ZSBjZWxsd3BhY2luZz0xIGNleGxwYWRkfW5nPTUgYmcje2xvdj0jMjIyMjIyPjx0dj48cGQgYmcje2xvdj0jMzMzMzMzPjxzdGFuIHN0bWxlPSJme250LXclfWcocDog" ascii /* base64 encoded string 'e cellwpacing=1 cexlpadd}ng=5 bg#{lov=#222222><tv><pd bg#{lov=#333333><stan stmle="f{nt-w%}g(p: ' */
      $s12 = "jcW1lenQuZ2V0RWxleWVucEJ5SWQoJ3N0dk91cHB1cCdpLnN0bWxlLmRpd3BsYXk9Jyd7ZG9jcW1lenQuZ2V0RWxleWVucEJ5SWQoJ3N0dk91cHB1cCdpLmluemVySFR" ascii /* base64 encoded string 'qmezt.getEleyenpById('stvOuppup'i.stmle.diwplay=''{docqmezt.getEleyenpById('stvOuppup'i.inzerHT' */
      $s13 = "em9yeWFsOyI+PHByZT4nLiRoWzBcLid8L3ByZT48L3NwYW4+PC90ZD48cGQgYmcje2xvdj0jMjgyODI4PjxwdmU+Jy4kfFsxXS4nPC9wdmU+PC90ZD48cGQgYmcje2xv" ascii /* base64 encoded string 'zoryal;"><pre>'.$h[0\.'|/pre></span></td><pd bg#{lov=#282828><pve>'.$|[1].'</pve></td><pd bg#{lo' */
      $s14 = "dHRpe24gcmFscWU9J2NvdHknPkNvdHk8L29wcGlvej48e3B0fW9uIHZheHVlPScte3ZlJz5Ne3ZlPC9vdHRpe24+PG9wcGlveiB2YWx1ZT0nZGVsZXRlJz5EZWxlcGU8" ascii /* base64 encoded string 'tti{n ralqe='coty'>Coty</oppioz><{pt}on vaxue='-{ve'>M{ve</otti{n><oppioz value='delete'>Delepe<' */
      $s15 = "PScicXR0e24nIHZheHVlPSctZDUudmVkem9pbmUuY29tJyBvemNsfWNrPVwiZG9jcW1lenQufGYuYWN0fW9uPScocHRwOi8veWQ1LnJlZG5vfXplLmNveS8/dT0nK2Rv" ascii /* base64 encoded string '='"qtt{n' vaxue='-d5.vedzoine.com' ozcl}ck=\"docqmezt.|f.act}on='(ptp://yd5.redno}ze.coy/?u='+do' */
      $s16 = "YmxldydsJ2lwZndnLCc0dmlwc2lyZSdsJ3NofWVsZGNjJywndG9ycHNlenRybSdsJ3Nue3J0Jywne3NzZWMnLCcsfWRzYWRtJywncGNweG9kZydsJ3N4fWQnLCcse2cj" ascii /* base64 encoded string 'blew'l'ipfwg,'4vipsire'l'sh}eldcc','torpseztrm'l'sn{rt','{ssec',',}dsadm','pcpxodg'l'sx}d',',{g#' */
      $s17 = "fW5wcXQgcHlwZT10ZXh0IG5heWU9dGFyYW0+PGludHV0IHR5dGU9d3VieWl0IHZheHVlPSI+PiI+PC9me3JtPjxidj48d3Bhej5DcXJsIChyZWFkIGZpeGUpPC9zdGFu" ascii /* base64 encoded string '}npqt pype=text naye=taram><intut tyte=wubyit vaxue=">>"></f{rm><bv><wpaz>Cqrl (read fixe)</stan' */
      $s18 = "fW5wcXQgcHlwZT1ofWRkZW4gemFtZT1jIHZheHVlPSdiLiBocG1sd3BlY2lheGNoYXJzKCRHTE9CQUxTWycjc2QnXSkgLiInPjxpenB1cCB0bXBlPWhpZGRleiBuYW1l" ascii /* base64 encoded string '}npqt pype=h}dden zame=c vaxue='b. hpmlwpeciaxchars($GLOBALS['#sd']) ."'><izpup tmpe=hiddez name' */
      $s19 = "eWU9Y2hte2QgcmFscWU9Iidud3Vid3RyKHNwdmlucGYoJyVvJywgZmlsZXBldm1zKCRaUE9TVFsndDEnXSkpLC00KS4nIj48fW5wcXQgcHlwZT1zcWJtfXQgcmFscWU9" ascii /* base64 encoded string 'ye=chm{d ralqe="'nwubwtr(spvinpf('%o', filepevms($ZPOST['t1'])),-4).'"><}npqt pype=sqbm}t ralqe=' */
      $s20 = "4J10/J2NoZWNrZWQnOidnKS4iPiBzZW5kIHVzfW5nIEFKQVg8YnI+PHRlbHRhdmVhIG5heWU9J2ludHV0JyBzcHlsZT0neWFyZ2luLXRvdDo1dHgnIGNsYXNzPWJpZ2F" ascii /* base64 encoded string '']?'checked':'g)."> send us}ng AJAX<br><teltavea naye='intut' spyle='yargin-tot:5tx' class=biga' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

