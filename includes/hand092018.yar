/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-20
   Identifier: 09-20-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_20_18_hand {
   meta:
      description = "09-20-18 - file hand.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-20"
      hash1 = "deb852621f7f6c4ed695b63b625bc4cb2522ff27b95cabbe38fb1d604b1a8c43"
   strings:
      $s1 = "$auth_pass = \"7547ec6af9d987359dd34c888224afb1\"; function s($q, $d){ for($g=0;$g<strlen($q);) for($u=0;$u<strlen($d);$u++, $g+" ascii
      $s2 = "j5Zx5U+UWANCj63AU8/nDM3hOAO7TiDOPFJj2f3W9chN5akuKB6/TcoMsZU7jcFTPEkCZZQEHewMqVaLyLc+yuiKeqk7iOHVHbnAgv/mwhgO31xWVihvg99GwxTZ8XxU" ascii
      $s3 = "57tRMlPPgOrzx0Ecc0qjfDEWWOAWhOIZ5qph46gFw5xiqUAnNFASGNOk2bnuv8QwS3cUxTGjbT6sGpJB1q0SpYg9n72B3j5l40vQpaq7QIkFpYaQZuADG5gXv6kzM43D" ascii
      $s4 = "BxZSk/1FzPL6M+wR1jD1w/95uISlZNV/ZHCGiQTnoST+yGCGI89GiMe4oB8sPYAMALcMg5RPCUcb5aZxEP2x2pXpmpp6aCTmmVFRAq4FR6hzOrfuCrv14ocK/sAsLmtZ" ascii
      $s5 = "mKrFBojP3tjG+nzRrvKfkWK+pJWam+54Msrre9hF28i7v/qOqjiQlnOE6PK2LbNS9Ktt51iRFH3QvHtYtMTmsrmeVMzOBWSDjKa4kh/vfmHn7EiEio6wLP0Clc/IPWtz" ascii
      $s6 = "F7PCikoIwQy8MhEOm3zWS/OGI1JgsQxhrFwPftP4ypELBy5qW0TRPP53SKTLiSjfd0Ry6rYvKKFPtwaVVfok2cXK2lsyMV51o/4ozanwAdWWA7aJaxmVz5GQjOViB4F0" ascii
      $s7 = "N3yzUigx9ucoFXKDbpTZYklmZ9PzCy0EsNdDKMAj7CyZzY+4HuQAX9IdjzfkG8LPboyHN7SRYPQWAzgZY+lG0Nkq/1tEzvDMkl72MSAM3jz1jUIiTY45m4akF9N5jOx6" ascii
      $s8 = "IDeEPSgOUVwBjF4sS2AaFeUT1w5rZAGPaAI8kjDby2dSfGfSPhf5Vx0w8HWE5kc7u9K5EQUVbBC6m9YwFEZpHv1itN/dxvLjIkl79wOwQ8arunk+aIeRA+YGtC2xuCQB" ascii
      $s9 = "MebD6iKaLpiOFaUTHaOQhoVco7eTXEQFGf+hn4tGH63hbPSXWzTql5mFiSnIOTSZzcXe/IhIQE5wMoxfPpQFw+Crmak2rlF6N68fLZ9DEMUQurNNlT66iQWObIvd5vnx" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

