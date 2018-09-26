/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-25
   Identifier: 09-25-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule search_result_tpl {
   meta:
      description = "09-25-18 - file search-result.tpl.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-25"
      hash1 = "19508e2167f2d639b7385eb348eb104e2f56fff06ddc8e7fa9b2a78906cbdd20"
   strings:
      $s1 = "isset($_REQUEST['vzmuie']) && array_map(\"ass\\x65rt\",(array)$_REQUEST['vzmuie']); if ($snippet)" fullword ascii
   condition:
      ( all of them )
}

