/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-13
   Identifier: kit
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://urlscan.io/result/c0a88f16-e0f8-4a30-bb55-d973e776cae0
   Reference: https://urlscan.io/result/9a1eae0b-bcfc-45a4-8ef3-8b16cfa3cc19
*/

/* Rule Set ----------------------------------------------------------------- */


rule _home_hawk_infected_12_13_18_phish1_maersk_kit_post {
   meta:
      description = "kit - file post.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-13"
      hash1 = "72946e59a710687acfddb28cad1e528a5aca0ab584b059cc7e93e37bfee256e2"
   strings:
      $s1 = "// if there are no errors process our form, then return a message" fullword ascii
      $s2 = "\"Password: \" . $pass . \"\\n\" ." fullword ascii
      $s3 = "\"==========Login=========\" . \"\\n\" ." fullword ascii
      $s4 = "// process.php" fullword ascii
      $s5 = "// DO ALL YOUR FORM PROCESSING HERE" fullword ascii
      $s6 = "// THIS CAN BE WHATEVER YOU WANT TO DO (LOGIN, SAVE, UPDATE, WHATEVER)" fullword ascii
      $s7 = "$data['message'] = 'Wrong Password! Try again!!';" fullword ascii
      $s8 = "$to = \"anonnymusrezult@gmail.com\";" fullword ascii
      $s9 = "// if there are any errors in our errors array, return a success boolean of false" fullword ascii
      $s10 = "// if any of these variables don't exist, add an error to our $errors array" fullword ascii
      $s11 = "$pass = $_POST[\"pass\"];" fullword ascii
      $s12 = "if (empty($_POST['pass']))" fullword ascii
      $s13 = "// validate the variables ======================================================" fullword ascii
      $s14 = "// return a response ===========================================================" fullword ascii
      $s15 = "// if there are items in our errors array, return those errors" fullword ascii
      $s16 = "mail($to, $subject, $message, $body, $headers);" fullword ascii
      $s17 = "$headers = \"email ENGLISH AUTO\";" fullword ascii
      $s18 = "$email = $_POST[\"email\"];" fullword ascii
      $s19 = "$errors['email'] = 'Email is required.';" fullword ascii
      $s20 = "$errors['pass'] = ' ';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 6KB and
         ( 8 of them )
      ) or ( all of them )
}
