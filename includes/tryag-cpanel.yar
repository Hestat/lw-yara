/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-13
   Identifier: 01-13-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_13_19_cpanel_shell {
   meta:
      description = "01-13-19 - file cpanel.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-13"
      hash1 = "19cfd29f5f32e84d7c7271a5629badaf77b630ba57a0d1f7e13d83f0a562e4d1"
   strings:
      $x1 = "function ccmmdd($ccmmdd2,$att)" fullword ascii
      $s1 = "$code = fread($sahacker, filesize($pathclass" fullword ascii
      $s2 = "$code=@str_replace" ascii
      $s3 = "system - passthru - exec - shell_exec</strong></td>" fullword ascii
      $s4 = "$error = @ocierror(); $this->error=$error" fullword ascii
   condition:
      ( uint16(0) == 0x683c and
         filesize < 70KB and
         ( 1 of ($x*) and 1 of them )
      ) or ( all of them )
}
