/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-02
   Identifier: shell1
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_02_18_shell_solus {
   meta:
      description = "shell1 - file solus.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-02"
      hash1 = "99f3776c10f35ebcf6729e346ee2d655aabbdebc494757fc3c6f8a5880f91dbc"
   strings:
      $s1 = "pdD1cJ2cobnVsbCxudWxsLCIxIix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN" ascii /* base64 encoded string 't=\'g(null,null,"1",this.param.value);return false;\'><input type=text name=param><input type=s' */
      $s2 = "lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+UG9zaXhfZ2V0cHd1aWQgKCJSZWFkIiAvZXRjL3Bhc3N3ZCk8L3NwYW4" ascii /* base64 encoded string '=param><input type=submit value=">>"></form><br><span>Posix_getpwuid ("Read" /etc/passwd)</span' */
      $s3 = "wdGZVMVJTUlVGTkxHZGxkSEJ5YjNSdllubHVZVzFsS0NkMFkzQW5LU2tnZkh3Z1pHbGxJQ0pEWVc1MElHTnlaV0YwWlNCemIyTnJaWFJjYmlJN0RRcHpaWFJ6YjJOcmI" ascii /* base64 encoded string 'tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb' */
      $s4 = "eval(\"?>\".base64_decode(\"PD9waHANCg0KDQokY29sb3IgPSAiI0ZFQ0QwMSI7DQokZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw0KQGRlZmluZSgnU0VM" ascii
      $s5 = "xS1RzTkNpQWdJQ0IzYUdsc1pTZ3hLU0I3RFFvZ0lDQWdJQ0FnSUdNOVlXTmpaWEIwS0hNc01Dd3dLVHNOQ2lBZ0lDQWdJQ0FnWkhWd01paGpMREFwT3cwS0lDQWdJQ0F" ascii /* base64 encoded string 'KTsNCiAgICB3aGlsZSgxKSB7DQogICAgICAgIGM9YWNjZXB0KHMsMCwwKTsNCiAgICAgICAgZHVwMihjLDApOw0KICAgICA' */
      $s6 = "uYW1lJ10uIjwvdGQ+PHRkPjxhIGhyZWY9J3N5bS9yb290L2hvbWUvIi4kdXNlclsnbmFtZSddLiIvcHVibGljX2h0bWwnIHRhcmdldD0nX2JsYW5rJz5zeW1saW5rIDw" ascii /* base64 encoded string 'ame']."</td><td><a href='sym/root/home/".$user['name']."/public_html' target='_blank'>symlink <' */
      $s7 = "+PHRkPiIuJGNvdW50KysuIjwvdGQ+PHRkPjxhIHRhcmdldD0nX2JsYW5rJyBocmVmPWh0dHA6Ly8iLiRkLicvPicuJGRkdC4nIDwvYT48L3RkPjx0ZD4nLiR1c2VyWyd" ascii /* base64 encoded string '<td>".$count++."</td><td><a target='_blank' href=http://".$d.'/>'.$ddt.' </a></td><td>'.$user['' */
      $s8 = "0ck91dHB1dCcpLnN0eWxlLmRpc3BsYXk9Jyc7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0ck91dHB1dCcpLmlubmVySFRNTD0nIi5hZGRjc2xhc2hlcyhodG1sc3B" ascii /* base64 encoded string 'rOutput').style.display='';document.getElementById('strOutput').innerHTML='".addcslashes(htmlsp' */
      $s9 = "rYng+PC90ZD48dGQ+PGEgaHJlZj0jIG9uY2xpY2s9IicuKCgkZlsndHlwZSddPT0nZmlsZScpPydnKFwnRmlsZXNUb29sc1wnLG51bGwsXCcnLnVybGVuY29kZSgkZls" ascii /* base64 encoded string 'bx></td><td><a href=# onclick="'.(($f['type']=='file')?'g(\'FilesTools\',null,\''.urlencode($f[' */
      $s10 = "vU1U1QlJFUlNYMEZPV1NrN0RRb2dJQ0FnWW1sdVpDaHpMQ0FvYzNSeWRXTjBJSE52WTJ0aFpHUnlJQ29wSm5Jc0lEQjRNVEFwT3cwS0lDQWdJR3hwYzNSbGJpaHpMQ0E" ascii /* base64 encoded string 'SU5BRERSX0FOWSk7DQogICAgYmluZChzLCAoc3RydWN0IHNvY2thZGRyICopJnIsIDB4MTApOw0KICAgIGxpc3RlbihzLCA' */
      $s11 = "XOXdaVzRnVTFSRVJWSlNMQ0krSmtOUFRrNGlPdzBLQ1FsbGVHVmpJQ1JUU0VWTVRDQjhmQ0JrYVdVZ2NISnBiblFnUTA5T1RpQWlRMkZ1ZENCbGVHVmpkWFJsSUNSVFN" ascii /* base64 encoded string '9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTS' */
      $s12 = "2YWx1ZSk7aWYodGhpcy5hamF4LmNoZWNrZWQpe2EobnVsbCxudWxsLHRoaXMuY21kLnZhbHVlKTt9ZWxzZXtnKG51bGwsbnVsbCx0aGlzLmNtZC52YWx1ZSk7fSByZXR" ascii /* base64 encoded string 'alue);if(this.ajax.checked){a(null,null,this.cmd.value);}else{g(null,null,this.cmd.value);} ret' */
      $s13 = "uY2xpY2s9ImcoXCdQaHBcJyxudWxsLG51bGwsXCdpbmZvXCcpIj5bIHBocGluZm8gXTwvYT48YnIgLz46ICcuKCRHTE9CQUxTWydzYWZlX21vZGUnXT8nPGZvbnQgY29" ascii /* base64 encoded string 'click="g(\'Php\',null,null,\'info\')">[ phpinfo ]</a><br />: '.($GLOBALS['safe_mode']?'<font co' */
      $s14 = "9Y2htb2QgdmFsdWU9Iicuc3Vic3RyKHNwcmludGYoJyVvJywgZmlsZXBlcm1zKCRfUE9TVFsncDEnXSkpLC00KS4nIj48aW5wdXQgdHlwZT1zdWJtaXQgdmFsdWU9Ij4" ascii /* base64 encoded string 'chmod value="'.substr(sprintf('%o', fileperms($_POST['p1'])),-4).'"><input type=submit value=">' */
      $s15 = "yZ2dMV2tpT3cwS2FXWWdLRUJCVWtkV0lEd2dNU2tnZXlCbGVHbDBLREVwT3lCOURRcDFjMlVnVTI5amEyVjBPdzBLYzI5amEyVjBLRk1zSmxCR1gwbE9SVlFzSmxOUFE" ascii /* base64 encoded string 'ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ' */
      $s16 = "DQWlQaVpUVDBOTFJWUWlLVHNOQ205d1pXNG9VMVJFUlZKU0xDQWlQaVpUVDBOTFJWUWlLVHNOQ25ONWMzUmxiU2duTDJKcGJpOXphQ0F0YVNjcE93MEtZMnh2YzJVb1U" ascii /* base64 encoded string 'AiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU' */
      $s17 = "pNDQudGlueXBpYy5jb20vMTE3NW5rai5naWYiIGlkPSJsb2dvIiBoZWlnaHQ9Ijc1JSIgd2lkdGg9IjkwJSIvPjwvZGl2PjxociBzdHlsZT0ibWFyZ2luOiAtNXB4IDE" ascii /* base64 encoded string '44.tinypic.com/1175nkj.gif" id="logo" height="75%" width="90%"/></div><hr style="margin: -5px 1' */
      $s18 = "JbnAiIHR5cGU9dGV4dCBuYW1lPWMgdmFsdWU9IicuaHRtbHNwZWNpYWxjaGFycygkR0xPQkFMU1snY3dkJ10pLiciPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4" ascii /* base64 encoded string 'np" type=text name=c value="'.htmlspecialchars($GLOBALS['cwd']).'"><input type=submit value=">>' */
      $s19 = "ocC5pbmlcJyxudWxsKSI+fCBQSFAuSU5JIHwgPC9hPjxhIGhyZWY9IyBvbmNsaWNrPSJnKG51bGwsbnVsbCxudWxsLFwnaW5pXCcpIj58IC5odGFjY2VzcyhNb2QpIHw" ascii /* base64 encoded string 'p.ini\',null)">| PHP.INI | </a><a href=# onclick="g(null,null,null,\'ini\')">| .htaccess(Mod) |' */
      $s20 = "5SUhCYk16QmRPdzBLSUNBZ0lITjBjblZqZENCemIyTnJZV1JrY2w5cGJpQnlPdzBLSUNBZ0lHUmhaVzF2YmlneExEQXBPdzBLSUNBZ0lITWdQU0J6YjJOclpYUW9RVVp" ascii /* base64 encoded string 'IHBbMzBdOw0KICAgIHN0cnVjdCBzb2NrYWRkcl9pbiByOw0KICAgIGRhZW1vbigxLDApOw0KICAgIHMgPSBzb2NrZXQoQUZ' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 8 of them )
      ) or ( all of them )
}
