/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-06
   Identifier: shell3
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_06_18_shell3_logo7 {
   meta:
      description = "shell3 - file logo7.jpg"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-06"
      hash1 = "22e6db49f1e2372dc133d15c5e8eff64e4a564c645a31e827e925fdf08e00178"
   strings:
      $x1 = "echo \"* * * * * curl -s"
      $x2 = "bash -s\" >> /tmp/cron || true && \\" fullword ascii
      $s2 = "curl -o /var/tmp/config.json" fullword ascii
      $s3 = "curl -o /var/tmp/suppoie http://" fullword ascii
      $s4 = "proc=`grep -c ^processor /proc/cpuinfo`" fullword ascii
      $s5 = "nohup ./suppoie -c config.json -t `echo $cores` >/dev/null &" fullword ascii
      $s6 = "ps aux | grep -vw suppoie | awk '{if($3>40.0) print $2}' | while read procid" fullword ascii
      $s7 = "/sbin/sysctl -w vm.nr_hugepages=`$num`" fullword ascii
      $s8 = "ps -fe|grep -w suppoie |grep -v grep" fullword ascii
      $s9 = "crontab -r || true && \\" fullword ascii
      $s10 = "chmod 777 /var/tmp/suppoie" fullword ascii
      $s11 = "rm -rf /tmp/cron || true && \\" fullword ascii
      $s12 = "crontab /tmp/cron || true && \\" fullword ascii
      $s13 = "cd /var/tmp" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 2KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

