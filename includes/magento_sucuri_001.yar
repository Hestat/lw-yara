/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-21
   Identifier: https://blog.sucuri.net/2018/06/magento-credit-card-stealer-reinfector.html
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule magento_sucuri_malware {
   meta:
      description = "sucuri magento malware"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-21"
   strings:
      $s1 = "error_reporting(0)" fullword ascii
      $s2 = "$b64 =" ascii
      $s3 = "$link =" ascii
      $s4 = "Cc.php" fullword ascii
      $s5 = "shell_exec" ascii
   condition:
          all of them 
}

