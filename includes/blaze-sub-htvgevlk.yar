/*
   YARA Rule Set
   Author: Brian Laskowski
   Date: 2021-03-03
   Identifier: 03-03-2021
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule htvgevlk {
   meta:
      description = "03-03-2021 - file htvgevlk.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2021-03-03"
      hash1 = "a1b58880c71d037eb2a1abddcc1bf4a7654a740a27bb8ddc9876fd7e398fe061"
   strings:
      $s1 = "($_COOKIE, $_POST)"
      $s2 = "jrnbyij"
      $s3 = "pklpyhc"
      
   condition:
      	$s1 and (#s2 > 5 or #s3 > 2)
}

