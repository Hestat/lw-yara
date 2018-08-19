/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */
/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_4dd6090f04 {
   meta:
      description = "08-18-18 - file 4dd6090f04.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-18"
      hash1 = "b3166068189c84f5ed00642fb82fb1ce77c8a51cfc3619fe4e75763cc088e73b"
   strings:
      $s1 = "function getDirContents($dir, &$results = array" fullword ascii
      $s2 = "if( isset($_REQUEST[\"test_url\"])" fullword ascii
      $s3 = "define( 'PCLZIP_ERR_USER_ABORTED'" fullword ascii
      $s4 = "$data = base64_decode("
   condition:
       all of them 
}

