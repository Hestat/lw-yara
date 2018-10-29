/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_188_120_231_151_2018_01_07a_shells_fack {
   meta:
      description = "shells - file fack.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "a2281fdbfeb4e0bef66c0d174fff9719253ff712c1b3d8cc554a5e6ac3caee89"
   strings:
      $s1 = "$fack = 'CgoKZXJyb3JfcmVwb3J0aW5nKDApOwovL2Vycm9yX3JlcG9ydGluZyhFX0FMTCk7CnNldF90aW1lX2xpbWl0KDApOwoKCgpjbGFzcyBJbmplY3RvckNvbXB" ascii
      $s2 = "oc2VsZWN0KzErZnJvbShzZWxlY3QrY291bnQoKiksY29uY2F0KChzZWxlY3QrKHNlbGVjdCsoU0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCgweDdlLDB4MjcsJTI3b2xvbG8" ascii /* base64 encoded string 'select+1+from(select+count(*),concat((select+(select+(SELECT+distinct+concat(0x7e,0x27,%27ololo' */
      $s3 = "0K2NvbmNhdCgweDdlLDB4MjcsJTI3b2xvbG8lMjcsMHgyNywweDdlKStGUk9NK2luZm9ybWF0aW9uX3NjaGVtYS5zY2hlbWF0YStMSU1JVCsxKSkrZnJvbStpbmZvcm1" ascii /* base64 encoded string '+concat(0x7e,0x27,%27ololo%27,0x27,0x7e)+FROM+information_schema.schemata+LIMIT+1))+from+inform' */
      $s4 = "zNTM2LDB4MzEzMDMyMzUzNDM4MzAzMDM1MzYsMHgzMTMwMzIzNTM0MzgzMDMwMzUzNiwoc2VsZWN0IGRpc3RpbmN0IGNvbmNhdCgweDdlLDB4MjcsdW5oZXgoSGV4KGN" ascii /* base64 encoded string '536,0x31303235343830303536,0x31303235343830303536,(select distinct concat(0x7e,0x27,unhex(Hex(c' */
      $s5 = "IRUNLIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKENBU1QoSUQgQVMgQ0hBUiksJyAnKSwnanphcnF0JyxJRk5VTEwoQ0FTVChJU19QRVJJT0QgQVMgQ0hBUik" ascii /* base64 encoded string 'ECK AS CHAR),' '),'jzarqt',IFNULL(CAST(ID AS CHAR),' '),'jzarqt',IFNULL(CAST(IS_PERIOD AS CHAR)' */
      $s6 = "faWQ9MiBVTklPTiBBTEwgU0VMRUNUIChTRUxFQ1QgQ09OQ0FUKCdxdmtxcScsSUZOVUxMKENBU1QoQUNUSVZFIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKEN" ascii /* base64 encoded string 'id=2 UNION ALL SELECT (SELECT CONCAT('qvkqq',IFNULL(CAST(ACTIVE AS CHAR),' '),'jzarqt',IFNULL(C' */
      $s7 = "yOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCUyOCcuJHBvbGUuJyUyQzB4MjclMkMweDdlJTI5KycuJGZyb20" ascii /* base64 encoded string '9%2Cconcat%28%28select+%28select+%28SELECT+distinct+concat%28'.$pole.'%2C0x27%2C0x7e%29+'.$from' */
      $s8 = "vdW50JTI4KiUyOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN0K2NvbmNhdCUyODB4N2UlMkMweDI3JTJDY291bnQoKiklMkM" ascii /* base64 encoded string 'unt%28*%29%2Cconcat%28%28select+%28select+%28SELECT+distinct+concat%280x7e%2C0x27%2Ccount(*)%2C' */
      $s9 = "vaHR0cDovL20ubG9hZGluZy5zZS9uZXdzLnBocD9wdWJfaWQ9NDE5MjAxMTExMTExMTExMTExMTExMTExMTExMTExMSUyMFVOSU9OJTIwU0VMRUNUJTIwMSwyLDMsNCw" ascii /* base64 encoded string 'http://m.loading.se/news.php?pub_id=4192011111111111111111111111111%20UNION%20SELECT%201,2,3,4,' */
      $s10 = "BU1QoQUdFTlRfSU5URVJWQUwgQVMgQ0hBUiksJyAnKSwnanphcnF0JyxJRk5VTEwoQ0FTVChEQVRFX0NIRUNLIEFTIENIQVIpLCcgJyksJ2p6YXJxdCcsSUZOVUxMKEN" ascii /* base64 encoded string 'ST(AGENT_INTERVAL AS CHAR),' '),'jzarqt',IFNULL(CAST(DATE_CHECK AS CHAR),' '),'jzarqt',IFNULL(C' */
      //$s11 = "tPnJldFsnc2xlZXAnXVsndmFsJ10uY2hyKDApLiInJiYnLyoqLyc9MHgyRjJBMkEyRiYmc2xlZVAoIi4kdGhpcy0+c2VjLiIpJiYnMSIpKSwnaGVhZGVyJywndGltZSc" ascii /* base64 encoded string '>ret['sleep']['val'].chr(0)."'&&'/**/'=0x2F2A2A2F&&sleeP(".$this->sec.")&&'1")),'header','time'' */
      //$s12 = "dLCR0aGlzLT5yZXRbJ3NsZWVwJ11bJ3ZhbCddLiInJiYnLyoqLyc9MHgyRjJBMkEyRiYmYkVuQ0hNQVJLKDI5OTk5OTksTWQ1KG5PVygpKSkmJicxIikpLCdoZWFkZXI" ascii /* base64 encoded string ',$this->ret['sleep']['val']."'&&'/**/'=0x2F2A2A2F&&bEnCHMARK(2999999,Md5(nOW()))&&'1")),'header' */
      //$s13 = "yb3IuJythbmQlMjhzZWxlY3QrMStmcm9tJTI4c2VsZWN0K2NvdW50JTI4KiUyOSUyQ2NvbmNhdCUyOCUyOHNlbGVjdCslMjhzZWxlY3QrJTI4U0VMRUNUK2Rpc3RpbmN" ascii /* base64 encoded string 'or.'+and%28select+1+from%28select+count%28*%29%2Cconcat%28%28select+%28select+%28SELECT+distinc' */
      //$s14 = "nc2xlZXAnXVsna2V5J10sJHRoaXMtPnJldFsnc2xlZXAnXVsndmFsJ10uIicmJicvKiovJz0weDJGMkEyQTJGJiZTbGVlUCgiLiR0aGlzLT5zZWMuIikmJicxIikpLCd" ascii /* base64 encoded string 'sleep']['key'],$this->ret['sleep']['val']."'&&'/**/'=0x2F2A2A2F&&SleeP(".$this->sec.")&&'1")),'' */
      $s15 = "raW5va2x1Ym5pY2hrYS5ydS9uZXdzX3ZpZXcucGhwP25ld3NfaWQ9MiBVTklPTiBBTEwgU0VMRUNUIChTRUxFQ1QgQ09OQ0FUKCdxdmtxcScsSUZOVUxMKENBU1QoQUN" ascii /* base64 encoded string 'inoklubnichka.ru/news_view.php?news_id=2 UNION ALL SELECT (SELECT CONCAT('qvkqq',IFNULL(CAST(AC' */
      $s16 = "oc2VsZWN0K2xlbmd0aCgnLiR2YWx1ZS4nKSsnLiRmcm9tIC4nKycuJHdoZXJlLicrbGltaXQrJy4kbGltaXQuJyksQ0hBUignLiR0aGlzLT5jaGFyY2hlcigifCIpLic" ascii /* base64 encoded string 'select+length('.$value.')+'.$from .'+'.$where.'+limit+'.$limit.'),CHAR('.$this->charcher("|").'' */
      $s17 = "ldFsnc2xlZXAnXVsnZmx0J11bJ3NwJ118fCR0aGlzLT5zZXRbJ3NsZWVwJ11bJ2ZsdCddWydhbiddKSR0aGlzLT5zZXRbJ3NsZWVwJ11bJ2ZsdCddWyd0cCddPXRydWU" ascii /* base64 encoded string 't['sleep']['flt']['sp']||$this->set['sleep']['flt']['an'])$this->set['sleep']['flt']['tp']=true' */
      $s18 = "JJG5ld19jaGVjayA9ICRuZXdfY2hlY2suIiUyZioqJTJmY09uVmVSdChpbnQlMmMoY2hhcigzMyklMmJjaGFyKDEyNiklMmJjaGFyKDMzKSUyYihjaGFyKDY1KSUyYmN" ascii /* base64 encoded string '$new_check = $new_check."%2f**%2fcOnVeRt(int%2c(char(33)%2bchar(126)%2bchar(33)%2b(char(65)%2bc' */
      $s19 = "ST00raW5mb3JtYXRpb25fc2NoZW1hLnNjaGVtYXRhK0xJTUlUKzEpKStmcm9tK2luZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMrbGltaXQrMCwxKSxmbG9vcihyYW5kKDA" ascii /* base64 encoded string 'OM+information_schema.schemata+LIMIT+1))+from+information_schema.tables+limit+0,1),floor(rand(0' */
      $s20 = "hc3Qoc2NoZW1hX25hbWUgYXMgY2hhcikpKSwweDI3LDB4N2UpIGZyb20gYGluZm9ybWF0aW9uX3NjaGVtYWAuc2NoZW1hdGEgbGltaXQgNCwxKSwweDMxMzAzMjM1MzQ" ascii /* base64 encoded string 'st(schema_name as char))),0x27,0x7e) from `information_schema`.schemata limit 4,1),0x3130323534' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 8 of them )
      ) or ( all of them )
}

