/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-28
   Identifier: english
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_27_18_phishing_english_error {
   meta:
      description = "english - file error.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-28"
      hash1 = "8eb8a7579fc8bc3b9bbad555e93acb58b8eb5eca935c4a645422e7db541bf02b"
   strings:
      $s1 = "<input type=\"hidden\" name=\"login\" value=\"<?php echo $_GET['email']; ?>\">" fullword ascii
      $s2 = "$domain = getDomainFromEmail($login);" fullword ascii
      $s3 = "$loginID = getloginIDFromlogin($login);" fullword ascii
      $s4 = "function getloginIDFromlogin($email)" fullword ascii
      $s5 = "$login = $_GET['email'];" fullword ascii
      $s6 = "$loginID = substr($email, 0, $pos);" fullword ascii
      $s7 = "$ln = strlen($login);" fullword ascii
      $s8 = "$len = strrev($login);" fullword ascii
      $s9 = "return $loginID;" fullword ascii
      $s10 = "6f%7a%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%34%70%78%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%72%64%65%72%2d%72%61%64%69%75" ascii /* hex encoded string 'oz-border-radius: 4px; -webkit-border-radiu' */
      $s11 = "20%33%70%78%20%23%30%30%30%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%78%2d%73%68%61%64%6f%77%3a%20%33%70%78%20%33%70%78%20%33%70%78%20" ascii /* hex encoded string ' 3px #000; -webkit-box-shadow: 3px 3px 3px ' */
      $s12 = "20%32%70%78%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%32%70%78%3b%20%2d%6b%68%74%6d%6c%2d%62%6f" ascii /* hex encoded string ' 2px; -webkit-border-radius: 2px; -khtml-bo' */
      $s13 = "78%2d%73%68%61%64%6f%77%3a%20%33%70%78%20%33%70%78%20%33%70%78%20%23%30%30%30%3b%20%2d%77%65%62%6b%69%74%2d%62%6f%78%2d%73%68%61" ascii /* hex encoded string 'x-shadow: 3px 3px 3px #000; -webkit-box-sha' */
      $s14 = "3a%34%35%70%78%3b%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%23%30%42%32%31%36%31%3b%20%62%6f%72%64%65%72%3a%20%73" ascii /* hex encoded string ':45px; background-color: #0B2161; border: s' */
      $s15 = "20%34%70%78%3b%20%2d%6b%68%74%6d%6c%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%34%70%78%3b%20%62%6f%72%64%65%72%2d%72%61%64" ascii /* hex encoded string ' 4px; -khtml-border-radius: 4px; border-rad' */
      $s16 = "2d%62%6f%78%2d%73%68%61%64%6f%77%3a%20%33%70%78%20%33%70%78%20%33%70%78%20%23%30%30%30%3b%20%62%6f%78%2d%73%68%61%64%6f%77%3a%20" ascii /* hex encoded string '-box-shadow: 3px 3px 3px #000; box-shadow: ' */
      $s17 = "79%3a%20%56%65%72%64%61%6e%61%3b%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%31%32%70%78%3b%20%63%6f%6c%6f%72%3a%23%66%66%66%66%66%66%3b" ascii /* hex encoded string 'y: Verdana; font-size: 12px; color:#ffffff;' */
      $s18 = "function getDomainFromEmail($email)" fullword ascii
      $s19 = "// Get the data after the @ sign" fullword ascii
      $s20 = "<?php echo $_GET['email']; ?>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_27_18_phishing_english_none {
   meta:
      description = "english - file none.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-28"
      hash1 = "b687aff9a134b489ece3dd28cfe006a14718faa050e23827324581e8df514b49"
   strings:
      $s1 = "<?php"
      $s2 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
      $s3 = "if (empty($login) || empty($passwd)) {" fullword ascii
   condition:
        ( all of them )
}


