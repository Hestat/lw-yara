/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-05
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_case25_shells_1119 {
   meta:
      description = "shells - file 1119.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "bcdebcaffcbd0ff1ff38b0d36c252b17b2c6856d45b1084c7b007fae5f26bdc6"
   strings:
      $s1 = "<?php $D=strrev('edoced_46esab');$s=gzinflate($D('7X1te9s2suh3/QqY1QZiItGSnHSzkinbTZxN7uZtY2fbXttHpSRKYi2RKkn5pa7/+50ZACT4JsvZ7t" ascii
      $s2 = "UOtUciBgDSdi1cx29sQissaItIRfq3oZyDwDFMek6F0zSJUpWGtRC6UbAOUSE6RVUZ3gIgnYzQMJPyePi+nsNaaOwcTt0AjuFTPDhDFp6ap6idh6Rmp919DshX40UQIT" ascii
      $s3 = "wiAk2QdhN24daA5qhEcK9HWqAgjY06BvVqUhS2Zh1P0M36ZERKvjQgSYooseWgMJQyroPIpvcMD0V4ymrkZL9gSjdSJk4x2YARM4GYiiaP5JE2DFOUhRn+xsMBU7/sF8" ascii
      $s4 = "dzOpHV6mGkGLND1PvJyb0v+D62R5yMoEE0RmX/xHMvkkdGY4D7DM1AtnBGIPEZn52ZqxRJxMn0rUnuI1QApouoldos56kbwuRl7z6rQZKTOjmHGuLv8Oj16y/GhRh1Uf" ascii
      $s5 = "qOeLOtZyydm6F7447XOCDD2Fu6AgAy6Wu48JZe3FBJS2fmjYe/rYPYjYbh2kcQzKRRmOUBZqtxAzo3Xfs03uynKA69VbRworkbNeo0COZd6Mbr0GdeNBSjItMP6A8gXD" ascii
      $s6 = "iGyWqOTBSCz8Pz+Pycn7cNMpkHqVhOJRVcgOZXU2jG8DdkY5wMBvTVJP0CTdHEHNWC+jds1lK6udOOBih9YnLVOUA6/Fgrdpd6pPTvlXcAzw6BvEEna7EYCJ9XllEiRR" ascii
      $s7 = "z00zCVzYyqqfpm4Bj+ZG+56aL3xeqG7roF0ZlenEg0Cm7k5QxQTaLqCAu27Uf2gEtyK6M2hrbXwEUxWMXR/zr6Sd1Y4DlX0EQwF9VgqK+MNjk7YoE82zk0EEgPzhk9Q2" ascii
      $s8 = "XSRov8r0wtrMggbd0oBoy6tlQ7wRQ2xgh2NP0CaqOwLd6BatCLnHQfOpzA0S8MyD2IFMKjW1e+U1iM76neicLywqdfs5az+S0GqSQhTiquttfrmKLyE/QUZXPg7iPX9e" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 50KB and
         ( all of them )
      ) or ( all of them )
}

rule news_parser_class {
   meta:
      description = "shells - file news_parser.class.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-05"
      hash1 = "1d47cfee87e3dded792528442c0a7d7b71df956697a87da4c389fc1f89821d78"
   strings:
      $s1 = "ygnYWN0aW9uJyAuICRfUE9TVFsnYSddKSApDQoJY2FsbF91c2VyX2Z1bmMoJ2FjdGlvbicgLiAkX1BPU1RbJ2EnXSk7DQpleGl0Ow0K\";" fullword ascii
      $s2 = "jNSdllubHVZVzFsS0NkMFkzQW5LU2tnZkh3Z1pHbGxJQ0pEWVc1MElHTnlaV0YwWlNCemIyTnJaWFJjYmlJN0RRcHpaWFJ6YjJOcmIzQjBLRk1zVTA5TVgxTlBRMHRGV" ascii
      $s3 = "mV0Y2goJGRiLT5xdWVyeSgnU0VMRUNUIENPVU5UKCopIGFzIG4gRlJPTSAnLiR2YWx1ZS4nJykpOw0KCQkJCQkkdmFsdWUgPSBodG1sc3BlY2lhbGNoYXJzKCR2YWx1Z" ascii
      $s4 = "iBwb3NpeF9nZXRwd3VpZCgkcCkge3JldHVybiBmYWxzZTt9IH0NCmlmICghZnVuY3Rpb25fZXhpc3RzKCJwb3NpeF9nZXRncmdpZCIpICYmIChzdHJwb3MoJEdMT0JBT" ascii
      $s5 = "Xh0YXJlYSxzZWxlY3R7IG1hcmdpbjowO2NvbG9yOiNmZmY7YmFja2dyb3VuZC1jb2xvcjojNTU1O2JvcmRlcjoxcHggc29saWQgJGNvbG9yOyBmb250OiA5cHQgTW9ub" ascii
      $s6 = "gkJCQlicmVhazsNCgkJCQljYXNlICdwZ3NxbCc6DQoJCQkJCSR0aGlzLT5xdWVyeSgnU0VMRUNUICogRlJPTSAnLiR0YWJsZSk7DQoJCQkJCXdoaWxlKCRpdGVtID0gJ" ascii
      $s7 = "mE7YmFja2dyb3VuZC1jb2xvcjojMjIyO21hcmdpbjowcHg7IH0NCmRpdi5jb250ZW50eyBwYWRkaW5nOiA1cHg7bWFyZ2luLWxlZnQ6NXB4O2JhY2tncm91bmQtY29sb" ascii
      $s8 = "3NwYWNlLCdDb3VyaWVyIE5ldyc7IH0NCmZvcm17IG1hcmdpbjowcHg7IH0NCiN0b29sc1RibHsgdGV4dC1hbGlnbjpjZW50ZXI7IH0NCi50b29sc0lucHsgd2lkdGg6I" ascii
      $s9 = "CRuOyRpKyspIHsNCgkJJG93ID0gQHBvc2l4X2dldHB3dWlkKEBmaWxlb3duZXIoJGRpckNvbnRlbnRbJGldKSk7DQoJCSRnciA9IEBwb3NpeF9nZXRncmdpZChAZmlsZ" ascii
      $s10 = "XNwbGF5Om5vbmU7JzonJykuIm1hcmdpbi10b3A6NXB4JyBpZD0nc3RyT3V0cHV0Jz4iOw0KCWlmKCFlbXB0eSgkX1BPU1RbJ3AxJ10pKSB7DQoJCWlmKGluX2FycmF5K" ascii
      $s11 = "$string = \"Z2xvYmFsICRhdXRoX3Bhc3MsJGNvbG9yLCRkZWZhdWx0X2FjdGlvbiwkZGVmYXVsdF91c2VfYWpheCwkZGVmYXVsdF9jaGFyc2V0LCRzb3J0Ow0KZ2xv" ascii
      $s12 = "$alphabet = \".hyib/;dq4ux9*zjmclp3_r80)t(vakng1s2foe75w6\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

