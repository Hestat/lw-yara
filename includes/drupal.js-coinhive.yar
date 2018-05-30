/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-05-30
   Identifier: 05-30-18
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_05_30_18_drupal_coinhive_malware {
   meta:
      description = "05-30-18 - file drupal.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-05-30"
      hash1 = "366b4d277b29c4ad47a7a37ea24871a07b5f97d4c85591ced73578e11b67d1d2"
   strings:
      $x1 = "var _0x8aa6=[\"\\x75\\x73\\x65\\x20\\x73\\x74\\x72\\x69\\x63\\x74\",\"\\x70\\x61\\x72\\x61\\x6D\\x73\",\"\\x5F\\x73\\x69\\x74\\x" ascii
      $s2 = "* See http://bugs.jquery.com/ticket/9521" fullword ascii
      $s3 = "allows increasing the size at runtime, or (3) if you want malloc to return NULL (0) instead of this abort, compile with -s ABOR" fullword ascii
      $s4 = "* to be processed, in order to allow special behaviors to detach from the" fullword ascii
      $s5 = "* behaviorName-processed, to ensure the behavior is detached only from" fullword ascii
      $s6 = "* loaded, feeding in an element to be processed, in order to attach all" fullword ascii
      $s7 = "* enables the reprocessing of given elements, which may be needed on occasion" fullword ascii
      $s8 = "* previously processed elements." fullword ascii
      $s9 = "* called by this function, make sure not to pass already-localized strings to it." fullword ascii
      $s10 = "* function before page content is about to be removed, feeding in an element" fullword ascii
      $s11 = "responseText = \"\\n\" + Drupal.t(\"ResponseText: !responseText\", {'!responseText': $.trim(xmlhttp.responseText) } );" fullword ascii
      $s12 = "statusText = \"\\n\" + Drupal.t(\"StatusText: !statusText\", {'!statusText': $.trim(xmlhttp.statusText)});" fullword ascii
      $s13 = "* Drupal.attachBehaviors is added below to the jQuery ready event and so" fullword ascii
      $s14 = "* default non-JavaScript UIs. Behaviors are registered in the Drupal.behaviors" fullword ascii
      $s15 = "60* 1e3};for(var _0x14b7x9=0;_0x14b7x9< this[_0x8aa6[4]][_0x8aa6[60]];_0x14b7x9++){this[_0x8aa6[4]][_0x14b7x9][_0x8aa6[59]]()};" fullword ascii
      $s16 = "function(){return this[_0x8aa6[4]][_0x8aa6[60]]> 0};_0x14b7x2[_0x8aa6[55]][_0x8aa6[90]]= function(){return /mobile|Android|webO" fullword ascii
      $s17 = "* Override jQuery.fn.init to guard against XSS attacks." fullword ascii
      $s18 = "* runs on initial page load. Developers implementing AHAH/Ajax in their" fullword ascii
      $s19 = "var baseUrl = protocol + '//' + location.host + Drupal.settings.basePath.slice(0, -1);" fullword ascii
      $s20 = "* See the documentation of the server-side format_plural() function for further details." fullword ascii
   condition:
      ( uint16(0) == 0x0a0d and
         filesize < 900KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

