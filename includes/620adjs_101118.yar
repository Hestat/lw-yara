/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-11
   Identifier: shell2
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_10_11_18_620ad_js {
   meta:
      description = "shell2 - file 33706bc2224b7c62a40b422eea79fc5b0e293b2b6041337d8c62eda0dfa620ad.bin"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-11"
      hash1 = "33706bc2224b7c62a40b422eea79fc5b0e293b2b6041337d8c62eda0dfa620ad"
   strings:
      $s1 = "OU1pnTnRoMEhTVjlvb1ZOY3l1d1IwMjBsazFFSUJYSmhVWWZQMG9DMGhiWnRza014NjF2bWYxcVAxdll" fullword ascii /* base64 encoded string 'SZgNth0HSV9ooVNcyuwR020lk1EIBXJhUYfP0oC0hbZtskMx61vmf1qP1vY' */
      $s2 = "3ejRRWEpFdWVHdnZ0bHhIWXR6RVp0cWZOYnVETkp3U0lHeVdaY2RyWGNRNHRaVmVwN2FuSW9CeVdZS04" fullword ascii /* base64 encoded string 'z4QXJEueGvvtlxHYtzEZtqfNbuDNJwSIGyWZcdrXcQ4tZVep7anIoByWYKN' */
      $s3 = "VK0JON0QzVVk0emJTUjFuWXFjU1RlOG5maGlYMW9CZmsyZXZ6STFhd21CWG1paEVFemJ4d0QrVU9Kb1B" fullword ascii /* base64 encoded string '+BN7D3UY4zbSR1nYqcSTe8nfhiX1oBfk2evzI1awmBXmihEEzbxwD+UOJoP' */
      $s4 = "4NjNcMTQxIik/JHkzZTMwNzZlKCRrYjMzNjBmZSgkZzQxMTRkM2QoIkNJVU1lZGdWUmlsS2IvZ2pFbWx" fullword ascii /* base64 encoded string '63\141")?$y3e3076e($kb3360fe($g4114d3d("CIUMedgVRilKb/gjEml' */
      $s5 = "jOC49IlwxNjAiOyRnNDExNGQzZC49Ilx4MzMiOyRrYjMzNjBmZS49Ilx4NjUiOyR0MWZiOWY2ZC49Ilx" fullword ascii /* base64 encoded string '8.="\160";$g4114d3d.="\x33";$kb3360fe.="\x65";$t1fb9f6d.="\' */
      $s6 = "TcmRqNmpTYWh0eWpKTVUvR0tvMjhjVFhXSnZ4cEhNVG1CN0lvMHkwM3NFZmRrT2t6T2NIdUVPRGhsU0p" fullword ascii /* base64 encoded string 'rdj6jSahtyjJMU/GKo28cTXWJvxpHMTmB7Io0y03sEfdkOkzOcHuEODhlSJ' */
      $s7 = "yYygkaTRlNjdhYWMoJHBkY2VlMGM4KCJceDJmXDEzNFx4MjhceDVjXHgyMlw1Nlx4MmFceDVjXHgyMlw" fullword ascii /* base64 encoded string 'c($i4e67aac($pdcee0c8("\x2f\134\x28\x5c\x22\56\x2a\x5c\x22\' */
      $s8 = "6UzVPTTRONUpYajhxczA3UzhBUzB6b1oxRWJDSkFWTXJpSFhLYWxCeGxLU25ablZHOForSFUwbFhpWnB" fullword ascii /* base64 encoded string 'S5OM4N5JXj8qs07S8AS0zoZ1EbCJAVMriHXKalBxlKSnZnVG8Z+HU0lXiZp' */
      $s9 = "2TnBCcmg1bkhxSjZGaDFYZzQ5VFM4cnJCM050eUFaRDJ0NmJWTEkwcjFrb09NdGN5UE11U1lOQzdDaVE" fullword ascii /* base64 encoded string 'NpBrh5nHqJ6Fh1Xg49TS8rrB3NtyAZD2t6bVLI0r1koOMtcyPMuSYNC7CiQ' */
      $s10 = "yeFd0cmFLTEVJTDlwa1htejdoQ0VYMTZuQ3o2bUV5aE5LVjZsTjA0SWQraUlZMGkvNW9sbWtFeDVQYWN" fullword ascii /* base64 encoded string 'xWtraKLEIL9pkXmz7hCEX16nCz6mEyhNKV6lN04Id+iIY0i/5olmkEx5Pac' */
      $s11 = "zIjskdDFmYjlmNmQ9IlwxNDYiOyR5M2UzMDc2ZT0iXDE0NyI7JGk0ZTY3YWFjPSJceDczIjskZ2VlYjg" fullword ascii /* base64 encoded string '";$t1fb9f6d="\146";$y3e3076e="\147";$i4e67aac="\x73";$geeb8' */
      $s12 = "OUkl2ei9FTlV0bjVTUDV1NU55VU9lZ1RyQUZieUI4eFlvV2tQQ254dzJiK3lDeWw5Yi9wZmVEKzZEVmt" fullword ascii /* base64 encoded string 'RIvz/ENUtn5SP5u5NyUOegTrAFbyB8xYoWkPCnxw2b+yCyl9b/pfeD+6DVk' */
      $s13 = "HbG1BSk82SVFBMWtmbXcyTWRmUFpwOGFzZDdySmtabVYyaktXYlRCMFFhWHBhQzg4b3BXN0o5U0U5UU5" fullword ascii /* base64 encoded string 'lmAJO6IQA1kfmw2MdfPZp8asd7rJkZmV2jKWbTB0QaXpaC88opW7J9SE9QN' */
      $s14 = "iIiwkdDFmYjlmNmQoJGdjNzhjYTZhKCRsYjYzNDJhNSkpKSkpLCJcNjJcNjFceDY0XDYwXHgzM1w2Nlx" fullword ascii /* base64 encoded string '",$t1fb9f6d($gc78ca6a($lb6342a5))))),"\62\61\x64\60\x33\66\' */
      $s15 = "uVFBKYVA4dkIwUEUrUWo0YzB2c2k0YU8xL1liNEE4c0hVMEkwMnFtTUlyNFU0ZzFqOEd3R0EzTU03Wkd" fullword ascii /* base64 encoded string 'TPJaP8vB0PE+Qj4c0vsi4aO1/Yb4A8sHU0I02qmMIr4U4g1j8GwGA3MM7ZG' */
      $s16 = "zdVlPTTA3eUpnYTY2YUpnazZmb2RFcjdHcWQvSkhrRURSbWtZam9qd2doV09Fc0gremtYdTdVRmROZUk" fullword ascii /* base64 encoded string 'uYOM07yJga66aJgk6fodEr7Gqd/JHkEDRmkYjojwghWOEsH+zkXu7UFdNeI' */
      $s17 = "6UTRaT2xFelBWWlNpb0xkdk9TREppNzRyTzRTOE5ROXROaTBqL3d1RDR4U3RRa3R5VW1RMkxybEcrZXF" fullword ascii /* base64 encoded string 'Q4ZOlEzPVZSioLdvOSDJi74rO4S8NQ9tNi0j/wuD4xStQktyUmQ2LrlG+eq' */
      $s18 = "xRXV1NTltRjg3UFBKYUJTNFkxQVJ1QUNoSXNySDE5QjhSZGYrNTkzdG1GZUpDczNmRmRZNTArZzJBc0Z" fullword ascii /* base64 encoded string 'Euu59mF87PPJaBS4Y1ARuAChIsrH19B8Rdf+593tmFeJCs3fFdY50+g2AsF' */
      $s19 = "2ZC49Ilx4NzMiOyRsYjYzNDJhNT0kZ2VlYjgzMGMoIlw1MCIsX19GSUxFX18pO0BldmFsKCRoM2JiZDg" fullword ascii /* base64 encoded string 'd.="\x73";$lb6342a5=$geeb830c("\50",__FILE__);@eval($h3bbd8' */
      $s20 = "yMFR0b0dpaEUzaDFaMFR2REszRkRCM0gwQ3ZsRDBrK3owWEwxRnBiZGdPRWVTblNRbjE0MnBmeWdZN0c" fullword ascii /* base64 encoded string '0TtoGihE3h1Z0TvDK3FDB3H0CvlD0k+z0XL1FpbdgOEeSnSQn142pfygY7G' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

