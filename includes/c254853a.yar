/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-25
   Identifier: 11-25-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule c254853a {
   meta:
      description = "11-25-18 - file c254853a.ico"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-11-25"
      hash1 = "8a3d52b376a67a7833906ab4307e6614747c5c636768fc92b29f46735cdaa43d"
   strings:
      //$s1 = "7*//*ap*/)/*382s*/ + 1/*bicrk*/)/*qe*/, 0, strlen/*7cyz*/(/*9*/$_oye1xlj/*6bnu*/)/*mi9js*//*4t*/)/*anrlf*//*2zp*/)/*sou9m*/;" fullword ascii
      //$s2 = "sryu%3Cj%3FA%27-tozz%3B%3D2%01q%26m%14a%279a%2F%7B2ptk%252iaov%28%7Cy3%7B3s%7Bplm7%28-x8%238.5%21wh%3E%21ttslcwl%29%2Ai-%3D%7B" fullword ascii
      $s3 = "$_7il4m0k = basename/*1*/(/*2ro*/trim/*ag*/(/*j*/preg_replace/*vz*/(/*ds*/rawurldecode/*o*/(/*s4r9*/\"%2F%5C%28.%2A%24%2F\"/*085" ascii
      $s4 = "//61c050381e48e384c943fc94caeb742bb83%3Dy%20ko%26sses%3C7%22%3A%3B%2Ad%60da%3B%0Bs%20%2A%23mpnfkit%20%3Er%3E%3E1ogha~ce%60i9ks%7" ascii

   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( all of them )
      ) or ( all of them )
}

