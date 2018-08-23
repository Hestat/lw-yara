/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-23
   Identifier: shell5
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_22_18_admin_backdoor_pomo {
   meta:
      description = "shell5 - file pomo.php3"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "6f986483b7dbfb173bb3744c19a839d793dd53248e09b9da63906f9e3e1fbb7b"
   strings:
      $s1 = "wp_redirect(get_bloginfo('wpurl') . '/wp-admin');" fullword ascii
      $s2 = "wp_set_current_user($user_id, $user_login);" fullword ascii
      $s3 = "echo \"You are logged in as $user_login\";" fullword ascii
      $s4 = "do_action('wp_login', $user_login);" fullword ascii
      $s5 = "$user_login = $user_info->user_login;" fullword ascii
      $s6 = "$user_ids = $wpdb->get_results($query_str);" fullword ascii
      $s7 = "$query_str = \"SELECT ID FROM $wpdb->users\";" fullword ascii
      $s8 = "require('../../wp-blog-header.php');" fullword ascii
      $s9 = "$user_info = get_userdata($user_id);" fullword ascii
      $s10 = "if (function_exists('get_admin_url')) {" fullword ascii
      $s11 = "wp_redirect(get_admin_url());" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule well_known_082218 {
   meta:
      description = "shell5 - file well-known.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "aaf89d834724969f174bfb65cf1503739794746f9904894cec8febd715baacd9"
   strings:
      $s1 = "'pTIwnJSfL2uupaZbWUWyp1fapzImW10cYvp8Y3EyrUEupzIuCwjiMTy2CwjiMz9loG4aB2WlMJSeB2Aup2HtVaAw' , " fullword ascii
      $s2 = "'qTyiovO2LJk1MG0vY2I0Ll9mp2tiVw5ZnJ51rP1mp2t8Y29jqTyiow4aB2IwnT8tWmjip2IfMJA0CwjiMz9loG48' , " fullword ascii
      $s3 = "$password = \"d6d9172da07e6c44c1fbcb571fd0a8f6\"; " fullword ascii
      $s4 = "'sFOzqJ5wqTyiovOhMvuuYTVcVUftpzHtCFOjpz9gpUDbVgQPinwQ+lVfLvx7VTyzXUWyXFO7VPDbW2qiWlxhqzSf' , " fullword ascii
      $s5 = "'CwjiMz9loG48MTy2VTAfLKAmCFWuL3EuoTjvVUA0rJkyCFWjLJExnJ5aBwujrQgjLJExnJ5aYKWcM2u0BwL4pUt7' , " fullword ascii
      $s6 = "'Vw48C3ObpPOyL2uiVUObpS91ozSgMFtcYvp8LaV+Wl4xK1ASHyMSHyfaH0IFIxIFK1ACEyEKDIWSW107Cm48Y2Ec' , " fullword ascii
      $s7 = "'qUV+WmgyL2uiVPp8Y3EuLzkyCwjiMz9loG4aB2yzXTAiqJ50XPEsHR9GISfaqUyjMKZaKFxtCvNjXFO7WT1uqTAb' , " fullword ascii
      $s8 = "'BlO9VU1zqJ5wqTyiovO0rUEmXT0fpPkuXFO7VUNtCFOmMPujXGftpzHtCFOjpz9gpUDboFkjXGftnJLbpzHcVUft' , " fullword ascii
      $s9 = "'JlqwnTIwnlqqYvpvCvp7VU1yL2uiVPp8nJ5jqKDtqUyjMG0vp3IvoJy0VvO2LJk1MG0vVR8tFlNvCwjiMz9loG48' , " fullword ascii
      $s10 = "'WGV3Y2pfVvpvXGftpzI0qKWhVUA0pwftsJM1ozA0nJ9hVTAxXTEcpvxtrlOxnKVtCFOmMPuxnKVcBlNxXPqxnKVa' , " fullword ascii
      $s11 = "'GHIQDHgSDxSaH2uOHHyWo1SSD0EYEHWOnRAbDISWIJ9EEHAODHSODHSOHwOBER9cDJ9FZQIJF1AOZRkdEKIAnHS5' , " fullword ascii
      $s12 = "'ozA0nJ9hVTSwqUZbpPkuYTLcVUftpPN9VUAxXUNcBlOzVQ0tp2DbMvx7VUWyVQ0tpUWioKO0XTLfpPx7VTyzXUWy' , " fullword ascii
      $s13 = "'VUMuoUIyCFYJgAQDVw48Y3ExCwjiqUV+WmgyL2uiVPp8Y3EuLzkyCwjiMz9loG4aB2yzXPElo3qmXFO7MJAbolNa' , " fullword ascii
      $s14 = "'DIIODHSODHSPZT1OHHyODHSODHSADHMEDHSODHSOp0caEHAODHSODHSRDHWMDHSODHSOGSAMDxSaDHSODHSOq0SL' , " fullword ascii
      $s15 = "'MTy2Cvp7MJAbolNaCTMipz0tozSgMG0vMaWgZFVtnJD9VzMloGRvVT1yqTuiMQ0vHR9GIPV+CUEuLzkyVTAfLKAm' , " fullword ascii
      $s16 = "* Language and charset conversion settings" fullword ascii
      $s17 = "'DHSODHSODz5ODHSOD1SODHSOFHSODHSAM3qEFHEOGHSODJqODHSOEHSODHSODHSODHSEDHSODHyODHSOL0SODHSO' , " fullword ascii
      $s18 = "'GHIaBRSSnKqQFatirHbjLzqODHSODGt2pxuFD1SWDzqODHSAMRIXDISPDHSODKu3HJgOM0SODH9dBF9zYl9cIIu3' , " fullword ascii
      $s19 = "'DHSODHSODHSOD0SODHSOM0SODHMaDHSOEPfiYmy2DJqODHSCrHAPDJcmDJqODHyODHSODIIODHSODxSODHSPDHSO' , " fullword ascii
      $s20 = "'APxcB3WyqUIlovOmpUWcoaEzXPpyYwWzVPphWTSlpzS5JlEzoT9ipy0fXPEvrKEypl9jo3pbZGNlAPkzoT9ipvtx' , " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 300KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_language_ru_082218 {
   meta:
      description = "shell5 - file master-language_ru.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-23"
      hash1 = "7d97b8ce81e08ab2ea6ee043f32a9c91a250baf2e356630c89708dfbe3c79e32"
   strings:
      $s1 = "$x($_POST['tb_id']);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( all of them )
      ) or ( all of them )
}
