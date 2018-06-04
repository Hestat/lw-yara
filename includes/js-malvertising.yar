rule _06_04_18_case119_js_malvertising {
   meta:
      description = "case119 - file plugin.min.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
   strings:
      $s1 = "var _0x2515=" ascii
      $s2 = "document"
      $s3 = "_0x2515" ascii
   condition:
      all of them 
}

