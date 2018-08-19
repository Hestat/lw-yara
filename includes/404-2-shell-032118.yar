/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-19
   Identifier: shell4
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_19_18_shell4_404 {
   meta:
      description = "shell4 - file 404.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-19"
      hash1 = "4c140d760b89b833939924ee800eca93d3c101ac3b427a9c89494fd38d44801e"
   strings:
      $s1 = "<?php eval (\"?>\".base64_decode(\"PD9waHANCi8qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXA0KfCogICAgICAgICBDb2RlciZCe" ascii
      $s2 = "aUpGTmpjbWx3ZEV4dlkyRjBhVzl1UDJFOWRYQnNiMkZrSm1ROUpFVnVZMjlrWlVOMWNuSmxiblJFYVhJaVBrUnZjM2xoSUZsMWEyeGxQQzloUGlCOElBMEtQR0VnYUhK" ascii /* base64 encoded string 'iJFNjcmlwdExvY2F0aW9uP2E9dXBsb2FkJmQ9JEVuY29kZUN1cnJlbnREaXIiPkRvc3lhIFl1a2xlPC9hPiB8IA0KPGEgaHJ' */
      $s3 = "Z2tkU2w3RFFvZ0RRb2dJQ0FnSUNBZ0lDUmphQ0E5SUdOMWNteGZhVzVwZENncE93MEtJQ0FnSUdOMWNteGZjMlYwYjNCMEtDUmphQ3hEVlZKTVQxQlVYMVZTVEN3a2RT" ascii /* base64 encoded string 'gkdSl7DQogDQogICAgICAgICRjaCA9IGN1cmxfaW5pdCgpOw0KICAgIGN1cmxfc2V0b3B0KCRjaCxDVVJMT1BUX1VSTCwkdS' */
      $s4 = "a0tDUmphRzF2WkN3a1ptbHNaU2twRFFvSkNRbDdEUW9KQ1FrSmNISnBiblFnSWp4eWRXNCtJRlJoYldGdFpHbHlJU0E4TDNKMWJqNDhZbkkrSWpzTkNna0pDWDFsYkhO" ascii /* base64 encoded string 'kKCRjaG1vZCwkZmlsZSkpDQoJCQl7DQoJCQkJcHJpbnQgIjxydW4+IFRhbWFtZGlyISA8L3J1bj48YnI+IjsNCgkJCX1lbHN' */
      $s5 = "ZEVRbDlPUVUxRlhDY3VLaXd1S2x3bktDNHFLVnduTGlwY0tTNHFPM3hwYzFVbkxDUmpiMlJsTENSaU1TazdEUW9rWkdJOUpHSXhXekZkV3pCZE93MEtjSEpsWjE5dFlY" ascii /* base64 encoded string 'dEQl9OQU1FXCcuKiwuKlwnKC4qKVwnLipcKS4qO3xpc1UnLCRjb2RlLCRiMSk7DQokZGI9JGIxWzFdWzBdOw0KcHJlZ19tYX' */
      $s6 = "N0RRb2tZMjlrWld4bGJtZG9kQ0E5SURFd093MEtkMmhwYkdVb1FDUnVaWGRqYjJSbFgyeGxibWQwYUNBOElDUmpiMlJsYkdWdVoyaDBLU0I3RFFva2VEMHhPdzBLSkhr" ascii /* base64 encoded string '7DQokY29kZWxlbmdodCA9IDEwOw0Kd2hpbGUoQCRuZXdjb2RlX2xlbmd0aCA8ICRjb2RlbGVuZ2h0KSB7DQokeD0xOw0KJHk' */
      $s7 = "aGJXVTlKMkpoY3ljZ2RIbHdaVDBuZEdWNGRDYytQR0p5UGp4bWIyNTBJR052Ykc5eVBTZHlaV1FuUGxOdmJpQkxhWE50WVNCRmEyeGxQQzltYjI1MFBpQWdQR1p2Ym5R" ascii /* base64 encoded string 'hbWU9J2JhcycgdHlwZT0ndGV4dCc+PGJyPjxmb250IGNvbG9yPSdyZWQnPlNvbiBLaXNtYSBFa2xlPC9mb250PiAgPGZvbnQ' */
      $s8 = "V0U0eFlraFJaMUJUUW1waFIyeHpXa1k1ZW1SSFVuWU5DbVJZVVhWamJWWm9Xa05uY0VOcFFXZEpRMEZuU1VOQlowbERRV2RKUjA1dllWZDRhMWd6VGpCYVJ6a3haRU0x" ascii /* base64 encoded string 'WE4xYkhRZ1BTQmphR2xzWkY5emRHUnYNCmRYUXVjbVZoWkNncENpQWdJQ0FnSUNBZ0lDQWdJR05vYVd4a1gzTjBaRzkxZEM1' */
      $s9 = "cVNVaENhR1JIWjJkaFdFMW5ZMjFXYzFsWVVuQmtiVlZPUTJkc04wUlJiMHBEVjA1dllqTkJiMHBHVW1oamJXUnNaRVZhY0dKSFZYQkpSMnh0UzBOU1ZWbFlTbTVhV0ZK" ascii /* base64 encoded string 'qSUhCaGRHZ2dhWE1nY21Wc1lYUnBkbVVOQ2dsN0RRb0pDV05vYjNBb0pGUmhjbWRsZEVacGJHVXBJR2xtS0NSVVlYSm5aWFJ' */
      $s10 = "MllXeDFaVHNpUGcwS0RRb0pJRkJoYzNOM2IzSmtPaUE4YVc1d2RYUWdkSGx3WlQwaWRHVjRkQ0lnYzJsNlpUMGlNVElpSUc1aGJXVTlJbUpwYm1Sd1lYTnpJaUIyWVd4" ascii /* base64 encoded string '2YWx1ZTsiPg0KDQoJIFBhc3N3b3JkOiA8aW5wdXQgdHlwZT0idGV4dCIgc2l6ZT0iMTIiIG5hbWU9ImJpbmRwYXNzIiB2YWx' */
      $s11 = "ajROQ2p3dlltOWtlVDROQ2p3dmFIUnRiRDROQ2p3L2NHaHdJRDgrRFFvOFAzQm9jQTBLRFFva1lXeHBZWE5sY3lBOUlHRnljbUY1S0Nkc1lTY2dQVDRnSjJ4eklDMXNZ" ascii /* base64 encoded string 'j4NCjwvYm9keT4NCjwvaHRtbD4NCjw/cGhwID8+DQo8P3BocA0KDQokYWxpYXNlcyA9IGFycmF5KCdsYScgPT4gJ2xzIC1sY' */
      $s12 = "YTIxVlNFcHdZbTVTVVZsWFpHeFRSMVpvV2tkV2VVdERTbXBKYVdzM1JGRnZTa05ZUW5saFZ6VXdTVVIzT0ZKVk5VVlBkekJMVUVkT2RscEhWU3RFVVc5T1EyeE9iR0p0" ascii /* base64 encoded string 'a21VSEpwYm5SUVlXZGxTR1ZoWkdWeUtDSmpJaWs3RFFvSkNYQnlhVzUwSUR3OFJVNUVPdzBLUEdOdlpHVStEUW9OQ2xObGJt' */
      $s13 = "bElIUnZJSE5sYm1RZ2IyNXNlU0IwYUdVZ2JHbHVheUJ3WVdkbERRb0pldzBLQ1FseVpYUjFjbTRnSmxCeWFXNTBSRzkzYm14dllXUk1hVzVyVUdGblpTZ2tWR0Z5WjJW" ascii /* base64 encoded string 'lIHRvIHNlbmQgb25seSB0aGUgbGluayBwYWdlDQoJew0KCQlyZXR1cm4gJlByaW50RG93bmxvYWRMaW5rUGFnZSgkVGFyZ2V' */
      $s14 = "V25CYVIxWjZTVWRGWjJKSGJIVmhlVUl3WVVoS2RtUlhaRzlKU0dSdllWZE9iMGxJVW05YVUwSnRZVmQ0YkVsSFRtaGlhVUpwV2xOQ2EySXpaSFZpUnpsb1drZFdhMHhu" ascii /* base64 encoded string 'WnBaR1Z6SUdFZ2JHbHVheUIwYUhKdmRXZG9JSGRvYVdOb0lIUm9aU0JtYVd4bElHTmhiaUJpWlNCa2IzZHViRzloWkdWa0xn' */
      $s15 = "dExTMHRMUzB0RFFwemRXSWdSRzkzYm14dllXUkdhV3hsRFFwN0RRb0pJeUJwWmlCdWJ5Qm1hV3hsSUdseklITndaV05wWm1sbFpDd2djSEpwYm5RZ2RHaGxJR1J2ZDI1" ascii /* base64 encoded string 'tLS0tLS0tDQpzdWIgRG93bmxvYWRGaWxlDQp7DQoJIyBpZiBubyBmaWxlIGlzIHNwZWNpZmllZCwgcHJpbnQgdGhlIGRvd25' */
      $s16 = "MGFYQmhjblJHYjNKdFJHRjBZU0FtSUNSWGFXNU9WRHNOQ2drSmNtVmhaQ2hUVkVSSlRpd2dKR2x1TENBa1JVNVdleWREVDA1VVJVNVVYMHhGVGtkVVNDZDlLVHNOQ2ds" ascii /* base64 encoded string '0aXBhcnRGb3JtRGF0YSAmICRXaW5OVDsNCgkJcmVhZChTVERJTiwgJGluLCAkRU5WeydDT05URU5UX0xFTkdUSCd9KTsNCgl' */
      $s17 = "TUV0SlEwRm5TVU5CWjJOSVNuQmlibEZuU1d4emNWaFRRa1ZrVnpGM1lWYzFia2xGUm5sYU0xWjBXbGMxTUdNeGVIVkphbk5PUTJsQlowbERRV2RKUTFKdllqTk9NRWxF" ascii /* base64 encoded string 'MEtJQ0FnSUNBZ2NISnBiblFnSWxzcVhTQkVkVzF3YVc1bklFRnlaM1Z0Wlc1MGMxeHVJanNOQ2lBZ0lDQWdJQ1JvYjNOMElE' */
      $s18 = "VFJXeFVWa05CTjFwWFRtOWllVUZ1VjNsMFpFbEdUalZqTTFKc1lsZHNkVnB0T0RaSlEyTTNTVWhXZFZsWE1XeEpRekZvVHpKV2FtRkhPRGRhVjA1dllubEJibGQ1ZEdS" ascii /* base64 encoded string 'TRWxUVkNBN1pXTm9ieUFuV3l0ZElGTjVjM1JsYldsdVptODZJQ2M3SUhWdVlXMWxJQzFoTzJWamFHODdaV05vYnlBbld5dGR' */
      $s19 = "dlkyRjBhVzl1UDJFOVluSjFkR1ZtYjNKalpYSWlQa0p5ZFhSbElFWnZjbU5sY2p3dllUNGdmQTBLUEdFZ2FISmxaajBpSkZOamNtbHdkRXh2WTJGMGFXOXVQMkU5WTJo" ascii /* base64 encoded string 'vY2F0aW9uP2E9YnJ1dGVmb3JjZXIiPkJydXRlIEZvcmNlcjwvYT4gfA0KPGEgaHJlZj0iJFNjcmlwdExvY2F0aW9uP2E9Y2h' */
      $s20 = "eklqNXZMUzB0V3lBZ0pFVmthWFJRWlhKemFXOXVJRjB0TFMxdlBDOW1iMjUwUGp3dllqNE5DZ2s4TDNSa1BnMEtDVHgwWkQ0TkNna0pKR2x1Wm04TkNnazhMM1JrUGcw" ascii /* base64 encoded string 'zIj5vLS0tWyAgJEVkaXRQZXJzaW9uIF0tLS1vPC9mb250PjwvYj4NCgk8L3RkPg0KCTx0ZD4NCgkJJGluZm8NCgk8L3RkPg0' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 1000KB and
         ( 8 of them )
      ) or ( all of them )
}
