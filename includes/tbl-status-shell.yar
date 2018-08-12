/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-11
   Identifier: status
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule tbl_status_webshell {
   meta:
      description = "status - file tbl_status.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "83135837a0f81a06a6713a385156255ebeb0f4067e98d142a12442279544e209"
   strings:
      $s1 = "$wp_nonce = isset($_POST['f_pp']) ? $_POST['f_pp'] : (isset($_COOKIE['f_pp']) ? $_COOKIE['f_pp'] : NULL);" fullword ascii
      $s2 = "$wp_kses_data = 'O7ZDrQwa6UbFoqfZpODFm%%EmMp9dJWPwTBXF8QYAZ5zK7zdrqsSuFfuD71elbShG+JYtYbXjbUhRMXhAl5DaK5OwyTJm+v3rdBQKiBBHMt0bnh" ascii
      $s3 = "if( isset($_POST['f_pp']) ) @setcookie( 'f_pp', $_POST['f_pp'] );" fullword ascii
      $s4 = "$ord = ord( $filter[$i] ) - ord( $wp_nonce[$i] );" fullword ascii
      $s5 = "66L+7GioDFcKxdMhnhYnoLRng+UxsCFlO98r3IetzfBMJo3ztZphbIBUljFTyw605eIAaFnH7sEbpGYngHHseI6i5AVr5ee8Be1UFAavxpy+JSPy5h1FrCxg6KR7Aqfs" ascii
      $s6 = "SAgqB81qiQJH5LLQ23wtzLuMliDYX7DXvYPj62C8H+4RyVGkd1kiqvDPnIGDtgx4xDd4X7s0YjQamEh+5DsPyiZDBBoU4lL5OEL4Kkwz52wY+S3dmOEOJzTTxlEzIxb5" ascii
      $s7 = "VA3qyv+8bXHlcVpGK9z3+J7ASAT4NR0xP6c9akHoyqLs96+YeihhzfMXGDd7UTQgpHWuRIElSxNOqlO1CLmdrdkSV1lq39JX2Jy7Jq8eHcQz7spYcnBco05x9Bm5SkKd" ascii
      $s8 = "function wp_admin_bar_header() { " fullword ascii
      $s9 = "$kses_str = str_replace( array ('%', '*'), array ('/', '='), $wp_kses_data );" fullword ascii
      $s10 = "wp_admin_bar_header();" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 70KB and
         ( all of them )
      ) or ( all of them )
}

