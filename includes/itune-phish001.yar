/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-11
   Identifier: form
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */


rule itunes_form_index_phish {
   meta:
      description = "form - file index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-08-11"
      hash1 = "1ca62a985149cb0ac5e62a4128a70399364aad9b4d6b6317b87e567cdc9dbaca"
   strings:
      $s1 = "<a href=\"http://www.apple.com/fr/privacy/\">Lire l'Engagement de confidentialit&eacute; d&rsquo;Apple</a>" fullword ascii
      $s2 = "'https://itunesconnect.apple.com/WebObjects/iTunesConnect.woa';" fullword ascii
      $s3 = "<input name=\"theAccountName\" value=\"<?php echo $_POST['theAccountName'];?>\" type=\"hidden\" />" fullword ascii
      $s4 = "<input name=\"theAccountPW\" value=\"<?php echo $_POST['theAccountPW'];?>\" type=\"hidden\" />" fullword ascii
      $s5 = "<!doctype html public \"-//w3c//dtd html 4.01 transitional//en\" \"http://www.w3.org/tr/html4/loose.dtd\">" fullword ascii
      $s6 = "'Password : '.$_POST['theAccountPW'].'<br />';" fullword ascii
      $s7 = "Store, l'Apple Store en ligne, iChat, et bien plus encore. Vos informations ne seront communiqu&eacute;es &agrave; personne, sa" fullword ascii
      $s8 = "<option value=\"Quel est votre num&eacute;ro porte-bonheur ?\">Quel est votre num&eacute;ro porte-bonheur ?</option>" fullword ascii
      $s9 = "<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">" fullword ascii
      $s10 = "<option value=\"Quel a &eacute;t&eacute; votre premier emploi ?\">Quel a &eacute;t&eacute; votre premier emploi ?</option>" fullword ascii
      $s11 = "<option value=\"Le nom de la rue dans laquelle vous avez grandi ?\">Le nom de la rue dans laquelle vous avez grandi ?</option>" fullword ascii
      $s12 = "<option value=\"Le nom de votre premi&egrave;re &eacute;cole ?\">Le nom de votre premi&egrave;re &eacute;cole ?</option>" fullword ascii
      $s13 = "<form method=\"post\" action=\"\" name=\"formPost\" onsubmit=\"return valider()\">" fullword ascii
      $s14 = "if (!document.formPost.Cvv.value.match(/^[0-9]{3}$/)){" fullword ascii
      $s15 = "document.formPost.Cvv.focus();" fullword ascii
      $s16 = "'Itunes ID : '.$_POST['theAccountName'].'<br />';" fullword ascii
      $s17 = "; si vous oubliez votre mot de passe ou si vous avez besoin de le r&eacute;initialiser.</p>" fullword ascii
      $s18 = "document.formPost.ExpirationMonth.focus();" fullword ascii
      $s19 = "document.formPost.securityResponse.focus();" fullword ascii
      $s20 = "<option value=\"Le nom du h&eacute;ros de votre enfance ?\">Le nom du h&eacute;ros de votre enfance ?</option>" fullword ascii
   condition:
      ( uint16(0) == 0xbbef and
         filesize < 30KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

