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

