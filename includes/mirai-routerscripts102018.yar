/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-20
   Identifier: scripts
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_20_18_scripts_dlink {
   meta:
      description = "scripts - file dlink"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-20"
      hash1 = "ea5cee148f7cbeb3eb4553b7fc2315c48873acb8322e412a344574e70c5f4e4c"
   strings:
      $x1 = "cd /tmp; wget"
      $x3 = "; chmod 777 sefa.mips; ./sefa.mips dlink.mips; rm -rf sefa.mips" fullword ascii
      $x2 = "cd /tmp; wget"
      $x4 = "; chmod 777 sefa.mpsl; ./sefa.mpsl dlink.mpsl; rm -rf sefa.mpsl" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and
         filesize < 1KB and
         ( 1 of ($x*) )
      ) or ( all of them )
}

rule infected_10_20_18_scripts_avtech {
   meta:
      description = "scripts - file avtech"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-20"
      hash1 = "4459ec5c40bd6bed326080ac388eb0c78e74fbc73b2bea7d4b948a2e4c6dea53"
   strings:
      $x1 = "cd /tmp; wget"
      $x2 = "; chmod 777 sefa.arm; ./sefa.arm avtech.arm; rm -rf sefa.arm" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and
         filesize < 1KB and
         ( 1 of ($x*) )
      ) or ( all of them )
}
