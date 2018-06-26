/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-26
   Identifier: scan
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule case131_scan_weeman {
   meta:
      description = "scan - file weeman.py"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-26"
      hash1 = "903555a99076d498894e1166063772f7600e22216c7159813b061d882c60725a"
   strings:
      $s1 = "printt(3, \"If \\'Weeman\\' runs sucsessfuly on your platform %s\\nPlease let me (@Hypsurus) know!\" %sys.platform)" fullword ascii
      $s2 = "from core.config import user_agent as usera" fullword ascii
      $s3 = "# weeman.py - HTTP server for phishing" fullword ascii
      $s4 = "#  along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
      $s5 = "from core.shell import shell_noint" fullword ascii
      $s6 = "#  the Free Software Foundation; either version 2 of the License, or" fullword ascii
      $s7 = "from core.shell import shell" fullword ascii
      $s8 = "parser.add_option(\"-p\", \"--profile\", dest=\"profile\", help=\"Load weeman profile.\")" fullword ascii
      $s9 = "# Copyright (C) 2015 Hypsurus <hypsurus@mail.ru>" fullword ascii
      $s10 = "#  but WITHOUT ANY WARRANTY; without even the implied warranty of" fullword ascii
      $s11 = "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
      $s12 = "#  You should have received a copy of the GNU General Public License" fullword ascii
      $s13 = "#  it under the terms of the GNU General Public License as published by" fullword ascii
      $s14 = "#  (at your option) any later version." fullword ascii
      $s15 = "#  Weeman is distributed in the hope that it will be useful," fullword ascii
      $s16 = "if sys.version[:3] == \"2.7\" or \"2\" in sys.version[:3]:" fullword ascii
      $s17 = "print(\"Sorry, there is no support for windows right now.\")" fullword ascii
      $s18 = "#printt(3, \"Running Weeman on \\'Mac\\' (All good)\")" fullword ascii
      $s19 = "#  GNU General Public License for more details." fullword ascii
      $s20 = "printt(1,\"Weeman has no support for Python 3.\")" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}

