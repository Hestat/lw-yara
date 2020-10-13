/*
   YARA Rule Set
   Author: Brian Laskowski
   Date: 2020-10-13
   Identifier: 10-13-2020
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule webshells_10_13_2020_emotet {
   meta:
      description = "10-13-2020 - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-10-13"
      hash1 = "26c393cbef2f262c7be3b7dd4556b4a693b3e3c4c43e8a8c9ff02bff195a2985"
   strings:
      $x1 = "$contentData = '7PwHVFvJtjaKyu0csBtjgoltosmNQWCCoN0mRxOEyLTJiGSiABHadhubIDA5C5NBAmGCCBKhbZOjQQgshMDkKEQUGR7ee/c5++xz9j73v+//73n3" ascii
      $s2 = "NP4uiXA4WPLIrC4almgQRun/zA35G/lHvBQtvGdCLqb8x7GKnTLMAap7qH6huobHj2TNb702eNtVkAfmpwrsp1Y5PUN2J9+uEm4xhCUQkM0yGqP7DcLvEJZCWAZhORDY" ascii
      $s3 = "GGpUqP11AdInRNV7eOWSOUlvWC9iLsJmjTX7x05CYwLhWTKzCIkdK3IvmR3hFdzv4efLZ2jcqLqh77L8aDjHyLTv9lIttXT7Wk+ircaNlDfZX8dKoQ8LOGgzHQMaFRXR" ascii
      $s4 = "QFf0dUn8sWl4aJ1BeIy77dDTjPB+wkacsPUpIB59ovIQXJbDX/f0S1//cQDKgxlD0hFwBD8+ZmzjAA/A9hk154BhxQGV/uesPYoaDBCuiARbB1nW6sbi2t8b0zmy2UX4" ascii
      $s5 = "CNyBJ3ADjsAGWGE7GffMjf4b6x/Hoz37hJst0gET27/47zploID7T+NHey96Cw9yktz/kfA34kf7T6IVFqjAeho/Wrqh0Fs6fuLfi/8/pj/a+lG00hRqsIaR11TBkF+V" ascii
      $s6 = "B/P5+mIf2+hoAilx5GqxjwfFJNHEcEOm2MfFMJDLZsSHSHxlmMAPoaWqixPoFM0Op3DzxB6eUeQQk9mXxXmyNQkJpKePEYewM+ZG0K/SJT7hGtMS+nPE0TgmJDCZMWYT" ascii
      $s7 = "5EucPP3FP1T+vDrk7TDZ7VFED/oB2Lx63D9up2Gfuyf1yEseXeSPY8qtR1AWyuWXnsgXOlWOXgfrmpvsbktP5tVYSH7/c7tAqly7nWDUP/rHdBHwlDy5K98u0IYqu6QF" ascii
      $s8 = "9v0DjJu1nknNcMqIiuea3K52gp7CnmerdR3sgj199mvS7zQkurI5Gag++dzyIKS01mITjtHTcsIkc9jqxxtrx9k7+gGVDC3iTEWaIltKTXYVZlf7PuFcP0c4pzVbB9ab" ascii
      $s9 = "WP2U/B+KI7m8Q29V878SROY57w+EaI+utmq4I3yCm7Qqfwa2FIrCIMGPnyua2sLbq3TEb1UtL676+y19rDIzn2xfEDPCUjWqPz2XwispKH9SqOqWjvZ86tNMdl2t2d4y" ascii
      $s10 = "RFFA9aKNdFQf5DVFtPooQm+6sHrQEuUqr10Ou5iiNWMHzIovt+GkLARKhQREbW2HKvnFwH2WoAOYRnp/aJqvpL5OnduJC7KiO7ViuVCRFeMZIR5qbUb1v7P7quPBoaiA" ascii
      $s11 = "xXRNmVhQG0G1IcgeT+PDvp98ucuRzS+YzipbT4d9czn8wsHyLLtfh+VZZv/Fo0fjaa5UaweZyXWhUuNlj49ECMaWZNIF5UdOOy2UzTKCcGEZypO7WF2T2U6HUpny+rue" ascii
      $s12 = "/17YMPb4GA5HV5gpv09OaEYe1LyyjSdbWDB/W9OWLljzZwAavlNDLXraysMKqVScPbqmNL+f3fqChRbgTV3Zq71dHhWxLBNFioPXXfm0qZiokBHG5d7Ytq1QqwtU8DwQ" ascii
      $s13 = "U8jryQydo2RjDQqbogO8RAtiZeChDv5zYGBlam+Fe9smmQjf/BoY17z/bhn5an5nDjchmWkDK8seGR9zub1Ngv3KOOMWSdObW2hjWNZuBFmgETrIAs/qRvtg+dKBuE3n" ascii
      $s14 = "vPF6Op/Kky1fTHrUTvuHWsbIlrs+aP5MTn9a7nwgoQf6SyjVhiRb3/Ww9KFakeTpdbayx+sdUPvqIlvuRlChThArW+56IJ6SrSjZBsO+mEwshlT7YNnttAfU8SFPyQoC" ascii
      $s15 = "ypKN+PybUJ23AYR2JJK3YTwk2nDixivnw7yj68eYpAmzh6IGb/HNby0sUhYa7uBzlKRaWsDBlkftpVghxlD+r3s3q2jgNaRL5gQNLd0k5p9TWH+nwvdt1aYIlHFJMzr1" ascii
      $s16 = "QecU3bxPLnXEYT0DLlCbEC1c9uRasz1npmeUBw+vfkn4zJrAiXbOwQ9CPylGWxzel6beHipLVcDNP6T4X4zNJBkRDAuOVxGzCFJjWmRL5Kd3/3PT6v8ZBNQ5XKa2557w" ascii
      $s17 = "qfyi2w2YLPUuo+hOTrBDXF034K4mdZHzunJzLOPCgkY0jdizyvP6unssk876fiuepTfw9qxLj6+q4RwvO99qN/HlvvI0/5wv81uvT63e3seN+farZ/tGb88HeYEeKutq" ascii
      $s18 = "X0JiTMSyPhJUIJGhoLogwd2h9HBe2E5dsY91eBCPQVnzQuwTEMkOpBtVWEqUETsylE/bOEqiwgaZmJD5c8VBvHmxsXwj0+MSBA8iMWJtj0lwWVA42zhEb5wEl5kYkYJN" ascii
      $s19 = "hqhrusrgN3muzSfUOfzMPdjKGjpKYqLfzaLhSm/aGdjtfZzhW0N/NErv3bz5BUu7VmdYosPy9Fsg5t0NORTN+KltrVEoOYnKnzI2sMoLuG3+V2Wi9GPJQ51k/3s6DQR/" ascii
      $s20 = "QrWSXQC+aOxDptx1QOOMPNn1CMpdD6qpbLqEypO7rlQ7ufquYGxJNl2MqXay5W5P+kc0PtStZcoXE9Qeye4fYfqYnHkMGxeqv+zmk0y1Y1NdZc97RSF9V07/KKoH7XSs" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and 4 of them
}
