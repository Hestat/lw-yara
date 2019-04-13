/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-04-12
   Identifier: 04-12-19
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule xaishell {
   meta:
      description = "04-12-19 - file xaishell.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-04-12"
      hash1 = "7da18c114e0df44f78723657a54e4f38aa576a4331fc63ea63598aa5bc5c69ab"
   strings:
      $x1 = "$xaisyndicate = \"7b12W+O40gD6ueds5j+4PZwOvEBJaRpzSxL2kAQIWGpfHtt6O4TgxEFv4sz0/e23V4stO2kWmjnnPe8dcxoSLaVFqUcqVqWqX3+Z66ieqlg7kv" ascii
      $s2 = "/* (\" Default pass:\" xaishell \") */ " fullword ascii
      $s3 = "mFZ0OKddhVjysaYRmxqhcxtDUmPltxDP7f9gCX0fLiCmRrw0YnUrR+jTZ2Ge8renUpqazTJr6pcUtnDwnsy0c3TB6ZgxztBGdw+FtHH0kzvZHmBvrWpXWwyU7sR7LjKs" ascii
      $s4 = "otjgDbzSMD8Ps2WWJM/+/BTkaKJSEJYqi5ysfzOiJQddLLBgSW0U+WKO53IBl4tjScosG85DKxci6OE+AiIUVbEgYhFfwOT+BCv6MFnoXhDhZiUkqPEcnl4HQ4vxZlj2" ascii
      $s5 = "yVsrTbcPLBYkXsJ4c3erhhA6q+7UzAqP4tUxzxgAF14/uNkm3Ab0APUoEIRCnib6J5S6hKUdE8aaG66iYHqMdhjQ/mNZZW2a1x2nHStLkZxDrrEt72D+qPZar1SK+FeZ" ascii
      $s6 = "lNT4ufTp5lz5M9CUINjyu/VZ/a5xkGS5mjz6rx9nxZjN+YccPeF0jsOJ0aH3GIs7oVYnAkJ+X4dzzc3j+CBdTDZ4De36cZ4gF8j5fa4I5FjLc74hJwdSCnTjsElr1O24" ascii
      $s7 = "/NoMoRTL6Gce3tq7SY4IJxB1zJ6+fI8vAS2EXcTvW46jwirLY8gQAXLAnyvVVA6JLH5Hq/vSLimJWkNq+jOHzIirCqQBU9UY1iHsHaVMpL/yZIKlU5WesAhoIdnX1PyW" ascii
      $s8 = "AR0hiddYY/osZfx+Iq2cCQPiozbRXfUibDpilduT8lMR+QT8PPQrmwerBS6rTwaCWbVZxpkr5s2ftp0A0NTQ8jg6V/95iVyD8feN7wPp2CLChZ5UR7tsHgV/BGNvTMaA" ascii
      $s9 = "+52W2lPrfUCspYsaPF/uWpvzKtCXgkMbw8akd25D/uPgtDfmVdlDE701PO/6b47e040qm7VGb4C2Jw2uOYQzYQKq2r71EFSWeDY53dFTlb61Z2yR8Uz2I5ArTOWJwxz8" ascii
      $s10 = "uphdshqE5phe8zJHYCy61sLHtsLjq2/b8nE5rF8TknCHt7oBvtF5LX8l65EoW/LoG2fRq50b/yqXz3dQSlMwIBaWFZ1e6vlEWcxKXg03ZS11fmwiHlIL+AJSHOChGoIJ" ascii
      $s11 = "eSmGPisfPSoc50A3cy+vjweYe7E3d9s2tapH3Q7b2O8pQZ4z8OUa83jTPQr1T/QrkNuBQab1IVxtTr975EHEtpB+UOs+3L8njfTw8RKwz1AuuTeI4HeduegM6XmO+IXB" ascii
      $s12 = "liT0junH69ZfQiAUmCFQY4UGCqY7vc920LN25ww4wge1PTw9KQMN5t3Wc20v/qnaZ4PsjEN/Mgg2lOGhxMs7xDIlrU14AVOwbvqT66MuDOeMgUebWmoKlw3Db0htL5rO" ascii
      $s13 = "AWSl6cT90a3KG5nTDeWzOrkB2SgFTgmEMLR1ttJXdYVudTkJUvJbJPN76rdvtYbdIHabNSUF7lgzVZnqJpPpn/JwJAf7cZBTT0f2vXUgfV1DH7Kv2Dllf08+grZstzdn" ascii
      $s14 = "pfhBzSjxVJtdbgk733LD16HfUebvN76x14M75qqqkWamqlqQWgDMcryspsFIKTW7PM9lyG32VKYddvhcKBSCdc9m2q/S2skUOvkQf8MKjzUhstwq9J+9cyYNa/rAT/9m" ascii
      $s15 = "HSG6//1+/NxJnAL4/CmdXv9+D4kb79Fd4u5clGFvA59mDPT2l0dh9UZx+KugXr6KOE7eerp7SNT+GB35vDyeu6fXygO+9UX2IyyLYrxWza8YSyCofQl6G6iWlS2zB8qa" ascii
      $s16 = "4E/eU1H/V7PvKW0Xvv2lGybu9/WphKEwjf8um8u+n//+faZR5pP7ZSP6zq/x0ShnXyj+7ynZplQFox+wuTEH81leAkLzFcTkTISTvM7muMg2U5M0m2WZaxm/MfkbInQB" ascii
      $s17 = "INVYyMTkvoMjZpyeFErG3JD4j8VpeqTUknjJ//aUK6nPHR/UWNchRm8++Ofz1l7J6o9WyhNuWDPQfc0iaOL2CjBvyplsfzStMpnhnW0VMdqUIFk3Bf0ee8p94pvjT8rl" ascii
      $s18 = "gflxWzZRiEg3gzf6uYt/XiDxCYfgmv/3Aku+zdu/iYAng8IV/x7MMcFRzPhDldRFvtsgMFXKZGzDKdTcflPW9RIV6BInx8DfiVdw1HpXG0NHdjp/rKGllJvEKUuwLBcf" ascii
      $s19 = "OAvF0J5uZvgUj+t9IFa+1GyOj/hhochoeOjJpvkzi+CmD5B0VrSi6A6GK3yQWBTTkWjLUefCY1dA7wkVXqo9bPAkflqCQ/WSKJfP95eF/b2nQqfET0wKmF50ZidPr/97" ascii
      $s20 = "JNqndu+Vv9YBNeMwEAxiwqeqABfswRuUeFW9cEr9WqGgMvdsA1qiUikpFDbem7qwDT+7j21Gm+bINtscZkkEgIVhSoI3lMryHe2d5lyr9wPPwXarBagmV19nmDYJ3dyK" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_04_12_19_Logon {
   meta:
      description = "04-12-19 - file Logon.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-04-12"
      hash1 = "6f1757cb95bf4261459cf829a0cb32688a9c328951bd054611f28ca10916e93e"
   strings:
      $s1 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      //$s2 = "$message .= \"--- http://www.geoiptool.com/?IP=$ip ----\\n\";" fullword ascii
      //$s3 = "Login2.php?$url&username=$username" fullword ascii
      //$s4 = "$message .= \"---------+ Office365 Login  |+-------\\n\";" fullword ascii
      //$s5 = "$headers = \"From: Salamusasa <tee@ttcpanel.com>\\n\";" fullword ascii
      //$s6 = "$send = \"stegmollersarah@gmail.com, halifax89@yandex.com\";" fullword ascii
      //$s7 = "$password = $_POST['password'];" fullword ascii
      //$s8 = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
      //$s9 = "header(\"Location: index.php?$url&username=$username\");" fullword ascii
      $s10 = "$hostname = gethostbyaddr($ip);" fullword ascii
      //$s11 = "$message .= \"Password : \".$password.\"\\n\";" fullword ascii
      //$s12 = "$message .= \"User Agent : \".$browser.\"\\n\";" fullword ascii
      //$s13 = "$forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
      //$s14 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
      $s15 = "$passchk = strlen($password);" fullword ascii
      //$s16 = "<title>403 - Forbidden</title>" fullword ascii
      //$s17 = "$username = $_POST['username'];" fullword ascii
      $s18 = "$ip = getenv(" fullword ascii
      //$s19 = "--+ Created BY Overlappin in 2018 +-" ascii
      $s20 = "elseif(filter_var($forward" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 7KB and
         ( 8 of them )
      ) or ( all of them )
}
