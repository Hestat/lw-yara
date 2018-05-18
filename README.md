# lw-yara

Yara rulset based on php shells and other webserver malware. 

# Installation instruction

 ```git clone https://github.com/Hestat/lw-yara.git```

# scanning using clamav with custom rules

example at https://laskowski-tech.com/2018/04/26/eitest-cleanup-part-2-using-clamav-and-custom-yara-rules/


 ```clamscan -ir -l /root/scanresults.txt -d /root/lw-yara/lw-rules_index.yar -d /root/lw-yara/lw.hdb /path/to/scan/```

In clamscan 

```-ir flag will only report infected files and will scan recursively

-d flag allows you to specify a custom database, here we have 2 a hash database and a yara ruleset

-l creates a log of the scan```

***need to have clamav 98 or newer to parse Yara signatures***

More info here:

https://laskowski-tech.com/2018/05/17/malware-databased-custom-malware-signatures/




# This is still work in progress

Includes an install script to allow for the rules to be added to the maldet scanner.

https://github.com/rfxn/linux-malware-detect

https://www.rfxn.com/projects/linux-malware-detect/

Can be used indepentent of maldet if yara is already installed.

To add to maldet run the install-rules.sh script.
