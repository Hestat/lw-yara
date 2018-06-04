/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-04
   Identifier: case115
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_06_04_18_case115_pass {
   meta:
      description = "case115 - file pass.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "8ba235a103b4fe43724627700b0a98090fdd604f4c975096f460285aaecf7934"
   strings:
      $s1 = "ethod=\"post\"><input type=\"text\" name=\"g__g_\" value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>" fullword ascii
      $s2 = "oP9xzgrUWQ455KjxUGC7TwCgGr7kukd2QjDpSGy33YI4e+LK5QdPH7g9e2LDeR8dYJ+2cPQaspyTv1mq" fullword ascii
      $s3 = "eSye00TQ7GbfTpcFAYimlc4AML8in9Dk6rOdISD16mBgGxcSA0A/ltnHduQBC4m14j5zz4YJ3VCLOmIg" fullword ascii
      $s4 = "7xRCyvW3ECsutYKPu1xjdlB4M2BftQZdHWNwBCIiHZWlEiZvubDbhdlLteOPOwLBSoagBrDyGuyfkU3W" fullword ascii
      $s5 = "mG/qqIk2c3wPzaQVSueYebZXq5S0bX+Agx3SB0yL/aHRe8wdAtC4NV7SzmskL90qegRrOcrC4L7WERfz" fullword ascii
      $s6 = "2AqIYrkuI2rCUQWPdzJpHhickkQNKaIrclX3Of/qSvktVcWYB6Jl+eFqQ68vZ+j9ji1DpR5nsN/NNHDj" fullword ascii
      $s7 = "WZlIlYFfLHK6Oeot4IZAAq8EGa6hcbsJF6F6ajoV7S+VUo+eDyuOCNQwZYOrancHsIvfaILmuw9Fmu7Z" fullword ascii
      $s8 = "X2U7+c7e3PO75SM04UiSYm4a9TVmqV4Ycx5L+OPcNiZwULpBIRGDCCAZbjPfN/Xr2WUELRbg/7eYEpuF" fullword ascii
      $s9 = "V3Da66hAEfYbo+OQY9lWTEWgBzDblzKHEF6M9e3C9ATS//77Y/wET7jtsp0XnPuKCwKsiaSGybCHuZEl" fullword ascii
      $s10 = "BPw/UEyxmpRdFoB5R0Zob3fjt//5wKrOdTPwzEcPfI11SaIFHq/pmDiyZX7J3kqdRE6SA64ZvZU/CqJt" fullword ascii
      $s11 = "w090ZCI8Yx3srTP1KTedjR52H420Gt772lzbm5J1bLMAznnV2//qYodb6r+r4Fno7BAhJVJxUWzVcQVa" fullword ascii
      $s12 = "IpUAF3pqT5+QNduq//mHMODR+XDNYbswldNe8ZJbDFf6Aera5rZHWVQQR/i2stOius9E9/1EqRs7U41y" fullword ascii
      $s13 = "1HWXuytC9//fFFJ/UGELdfON2EmgHPtEBp02g7S7AQPhQGYpKrpp8sF1RO1UtTyZF0ebHypdWjGACPx3" fullword ascii
      $s14 = "R/d+PLLjtyB3N5RY2HQfZ09zeLtxb69fDfgXtSDmk7TAnDeasxRl/I4zzwjihgUmGaZGuFegcwIW24bu" fullword ascii
      $s15 = "Wail1S7z+/lhDGYv2b8OxhJUVwA8eiZ/rBi7/trxk/q5uABymJNW0qSUzZgk7/A/RMK+5Py1IlYhg5qx" fullword ascii
      $s16 = "QDWQCraGL/ZsBRIDDu3Dky5SCnCkib05Xq5kMW9R6a/C/+6h/X8mT+9HkAYmSKzV6R3wv4utRAwyWzp5" fullword ascii
      $s17 = "9vg4+dxL5doJSTw/2/vr8dlnBqxgxRNJe6LNb8kTeWSLcVD0IZvPEdHRWs3Q3Kyc+iyDnHgJro5LgIln" fullword ascii
      $s18 = "UOnOK8gzQzAkt8belqr6Ak8HcQXNCueILPbGYDLjBOytcPl33XeXcBYgN7dXD12VnF4oXd0W4+9/p/MA" fullword ascii
      $s19 = "utkxax8uTwnFfSMkQ1st+VwAKuo68/Y/kw/MKAYsGfMEvuA4Mn2eMiO0STTqMbRVG+Ud0hvlU/pwievk" fullword ascii
      $s20 = "w3wd5iQIs/rpw4T/V/JZfFYriedCYfoOPign4lFZoNNqgkJ5ZT5IEslEKM7z+LlBkEPzw0+bhpb67LtC" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 60KB and
         ( 8 of them )
      ) or ( all of them )
}

