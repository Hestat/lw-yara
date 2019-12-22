/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-03-01
   Identifier: 03-01-19
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://maxkersten.nl/binary-analysis-course/malware-analysis/emotet-droppers/
*/

/* Rule Set ----------------------------------------------------------------- */

rule emotet_dropper2 {
   meta:
      description = "03-01-19 - file emotet-dropper2.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-01"
      hash1 = "0336745712f8e6c27dc7691c6d2bd938e8d4962c172f901124f18a9d8bd10ca8"
   strings:
      $s1 = "6576616c28677a696e666c617465286261736536345f6465636f64652822" ascii /* hex encoded string 'eval(gzinflate(base64_decode("' */
      $s2 = "echo $commandPart1 . \"[base64-encoded-value-here]\" . $commandPart2 . \"\\n\";" fullword ascii
      $s3 = "file_put_contents(\"/home/libra/Desktop/emotet/stage4.php\", (gzinflate(base64_decode(''))));" fullword ascii
      $s4 = "$commandPart1 = decode('6576616c28677a696e666c617465286261736536345f6465636f64652822');" fullword ascii
      $s5 = "echo \"Command equals:\\n\";" fullword ascii
      $s6 = "222929293b" ascii /* hex encoded string '")));' */
      $s7 = "$commandPart2 = decode('222929293b');" fullword ascii
      $s8 = "for ($i = 0, $n = strlen($stringToDecode); $i < $n; $i+= 2) {" fullword ascii
      $s9 = "$output.= pack('H*', substr($stringToDecode, $i, 2));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule emotet_dropper3 {
   meta:
      description = "03-01-19 - file emotet-dropper3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-01"
      hash1 = "1673f455fb491289c298b4ff52a76e979da0531e93d65b93c922a80190f247ca"
   strings:
      $s1 = "$sp6345e2 = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';" fullword ascii
      $s2 = "private $contentName_ = 'iMDbapCVgUb.exe';" fullword ascii
      $s3 = "echo $sp58859d->execute();" fullword ascii
      $s4 = "'(?:Apple-)?(?:iPhone|iPad|iPod)(?:.*Mac OS X.*Version/(\\\\d+\\\\.\\\\d+)|;" fullword ascii
      $s5 = "header('Content-Type: ' . $this->contentType_);" fullword ascii
      $s6 = "header('Content-Disposition: attachment;" fullword ascii
      $s7 = ".*((?:Debian|Knoppix|Mint|Ubuntu|Kubuntu|Xubuntu|Lubuntu|Fedora|Red Hat|Mandriva|Gentoo|Sabayon|Slackware|SUSE|CentOS|BackTrack" fullword ascii
      $s8 = "'(?:(?:Orca-)?Android|Adr)[ /](?:[a-z]+ )?(\\\\d+[\\\\.\\\\d]+)'," fullword ascii
      $s9 = "private $content_ = '[omitted due to size]';" fullword ascii
      $s10 = "$sp7c7c2a = json_decode(fread($spdfc158, $spe8c644) , true);" fullword ascii
      $s11 = "ini_set('max_execution_time', 0);" fullword ascii
      $s12 = "?: Enterprise)? Linux)?(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
      $s13 = "'VectorLinux(?: package)?(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
      $s14 = "'CYGWIN_NT-5.2|Windows NT 5.2|Windows Server 2003 / XP x64'," fullword ascii
      $s15 = "'Darwin|Macintosh|Mac_PowerPC|PPC|Mac PowerPC|iMac|MacBook'" fullword ascii
      $s16 = "header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');" fullword ascii
      $s17 = "return base64_decode($this->content_);" fullword ascii
      $s18 = "'Arch ?Linux(?:[ /\\\\-](\\\\d+[\\\\.\\\\d]+))?'," fullword ascii
      $s19 = "header('Expires: Tue, 01 Jan 1970 00:00:00 GMT');" fullword ascii
      $s20 = "private $contentType_ = 'application/octet-stream';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 10KB and
         ( 8 of them )
      ) or ( all of them )
}

rule emotet_dropper1 {
   meta:
      description = "03-01-19 - file emotet-dropper1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-03-01"
      hash1 = "0311b2d34851ab3ba7f9f1ecd77a3bf0effbd52e8d4d2c20e30f9719bb7dcb9c"
   strings:
      $s1 = "6576616c28677a696e666c617465286261736536345f6465636f64652822" ascii /* hex encoded string 'eval(gzinflate(base64_decode("' */
      $s2 = "222929293b" ascii /* hex encoded string '")));' */
      $s3 = "$n5c62c1bcb81d1 = fn5c62c1bcb819b('6576616c28677a696e666c617465286261736536345f6465636f64652822');" fullword ascii
      $s4 = "eval($n5c62c1bcb81d1" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-12-22
   Identifier: 12-22-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_hawk_infected_12_22_19_image {
   meta:
      description = "12-22-19 - file image.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "ed4e15e61e44506cd384524c8548522f30c9ff9635bb37fb4dcb8c73764ede85"
   strings:
      $s1 = "/*4fdde239a36aa4d71f1e9570d9228bdc5f49b6de01950679e52f8b26a6fe32b4 */?><?php $ZpvfC9758 = \"/mhol(x8v6fzu.5iryn*bq49gesd3_20tkpw" ascii
      $s2 = "k/iOZ2gEZbaI3gTK4giWlqT472T9/tHO9ZsqlERni1p3Zv5JDAO/b7MzxQTQWCSOp8BTtOp2/sUBFDZK8m0VVg51M1shDLlRgFBd5TtnfqG2+evzH24w2UbBCg2V49Lk" ascii
      $s3 = "iozkP/lT90J+W4zX3XKZtb0KOG7bnDSasH/eYE7a2BH4yNsRON/H5r6odR+w0Q09wP+hvGljuZziIjupk6rSn/akzsMXtry8nhrAuoGle2N3NaVrtttbfWEDL8gSrbNK" ascii
      $s4 = "3HnFFMmK7HfdeuNGsOdRrbG11loggk3rDUa7GdmS7GE+s3Ftg4/4KGW+NEe7VME3OtwmcTxR0gdc2VTrZQAoTYMKQwwnvkbmHw2CPYTK5T2OTur7CmRX5wU0MnoPJqQx" ascii
      $s5 = "u6Fk+wXEDA6qKA9G15gBBRNwxnTm3iRCokin6jO23OrHt0Ej6YeYnpzLCH5hEe/ct+AgFYY/sSjVimZAMDUhraxUxvohG20wpm3Rv4E9nAlqzh3y7m6SZ/mvB3QpDIyw" ascii
      $s6 = "RRCHPrhCzGhYUuNzwkaNbyJ8m+YelibA7E1KyRPZLJIjAKaxBIpQlNlGChL7dJFya1rM9J2heLjBEtDLl4TuWL0KDd7ieMy8jMkOykr/I6Ro18GBPnRpKXGTQJKPidL4" ascii
      $s7 = "4fdde239a36aa4d71f1e9570d9228bdc5f49b6de01950679e52f8b26a6fe32b4" ascii
      $s8 = "lEmJZTNKt6LGiSc4TPWfAxotM5VpLgTVXq6oyzDIOhUmKYKcEbinWdW0hOsUJEQoGlwj9qomgEVqsrzLBhqUOp8BdhtYKmBR0cWpI6BMWVpnY0gg9EuTDSzGohZ35NWn" ascii
      $s9 = "935/0NXEzzuvixhbmeUg9s0AzF9RfkVIQPY9dvW0mPYQp82Zr4UEZaoiXRpVI1QDRuNOsEJ6EgzJ0s+6g7iewAFrBWp+vZk8v2uSrVUB9urVFFW7wyWroQaNlgr7jQ4X" ascii
      $s10 = "lBGDLXttbsmHtJ3ccYXHIMbp2d7q8+wtVZMeaD95dHB49Wj+NfZ/irN3308GHCO/xprBVTxgMa6ti9UTmpzg6hPyNnLE97pTSai2z5xEi43ZZp1ahIDUQ5q5ZV4LValP" ascii
      $s11 = "SlEIHTe4PWQ+XSRAnrQH1wRQFOXEi8Uk2pyqmcEmq0LaKOmiABbhh8pySfz3IgQrC/qhpksQlLRdb+QQEPGAldeQqcOmVSOGEkDdYVY6/BkGOAKOCFDOpL6khY7iFLdL" ascii
      $s12 = "<?php /*2f2512d8c52ceb5320bf4012b2bbeb10b41209ab*/" fullword ascii
      $s13 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
      $s14 = "7uzf8H'\".$zwZxFb7128));$c255($Q8500,array('','}'.$Tx4853.'//'));" fullword ascii
      $s15 = "2f2512d8c52ceb5320bf4012b2bbeb10b41209ab" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 80KB and
         ( 8 of them )
      ) or ( all of them )
}

rule _home_hawk_infected_12_22_19_user_emotet {
   meta:
      description = "12-22-19 - file user.php Emotet php serverside downloader file"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-12-22"
      hash1 = "30ed790766929a1be2d3a0095be41f3a1b7819505b826f779e109396236bad75"
   strings:
      $s1 = "goto" fullword ascii
      $s2 = "<?php function" fullword ascii
      $s3 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
      $s4 = "63e110ac5f971e41e77ef127575337d8aaeeae3b" ascii
      $s5 = "be5a8488b06f0640a63c80223a12d13e3d309f4d" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 2 of them )
      ) or ( all of them )
}

