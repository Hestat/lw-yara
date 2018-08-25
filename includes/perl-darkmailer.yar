/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-25
   Identifier: .proba
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_25_18_darkmailer__proba_install {
   meta:
      description = ".proba - file install.sh"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "25d996431965b818ade25fc03fdb756e6e58306bddcda7e32b1f69dcb5d4846e"
   strings:
      $s1 = "wget -O-  --no-check-certificate http://cpanmin.us | perl - -l ~/perl5 App::cpanminus local::lib" fullword ascii
      $s2 = "echo 'eval `perl -I ~/perl5/lib/perl5 -Mlocal::lib`' >> ~/.profile" fullword ascii
      $s3 = "declare -x HOME=\"$this\"" fullword ascii
      $s4 = "echo 'export MANPATH=$HOME/perl5/man:$MANPATH' >> ~/.profile" fullword ascii
      $s5 = "eval `perl -I ~/perl5/lib/perl5 -Mlocal::lib`" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}

rule infected_08_25_18_darkmailer__proba_send {
   meta:
      description = ".proba - file send.sh"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "2474d6f0ec11bda8df544653d8001380ad63540b2e3fefad85204593d1c88b15"
   strings:
      $s1 = "perl -Mlib=${this}/perl5/lib/perl5/ send2.pl body.html list.txt" fullword ascii
      $s2 = "declare -x HOME=\"$this\"" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 1KB and
         ( all of them )
      ) or ( all of them )
}


rule infected_08_25_18_darkmailer__proba_send2 {
   meta:
      description = ".proba - file send2.pl"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-25"
      hash1 = "1f03fcef96ec0b0300e4b2adfdcf19bb7767afbb08f0e0d528def7cfa0dec323"
   strings:
      $s1 = "my $processid = $forkmanager->start() and next;" fullword ascii
      $s2 = "my $Subject = 'REVENUE Tax refund - 490,99 EUR'; # subject for mails" fullword ascii
      $s3 = "print \"perl send.pl <email_body_file> <email_list_file> <threads>\\n\";" fullword ascii
      $s4 = "'content-type' => \"text/html; charset=\\\"iso-8859-1\\\"\"" fullword ascii
      $s5 = "print \"It works like this:\\n\";" fullword ascii
      $s6 = "my $From = '--REVENUE--<support@deliveroo.ie>'; # from addr" fullword ascii
      $s7 = "print \"[+][\".(localtime).\"] Started with $threads threads \\n\\n\";" fullword ascii
      $s8 = "my $forkmanager = new Parallel::ForkManager($threads);" fullword ascii
      $s9 = "if  (!$threads){ $threads = \"10\";}" fullword ascii
   condition:
      ( uint16(0) == 0x7375 and
         filesize < 4KB and
         ( all of them )
      ) or ( all of them )
}

