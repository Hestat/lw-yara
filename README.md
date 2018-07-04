# lw-yara

Yara rulset based on php shells and other webserver malware.

I will be moving to a new role soon which will take me away from front line server investigations. If you would like to keep this dataset up to date report back new malware using my scanner:

 https://github.com/Hestat/blazescan

Using the following will allow you to report new malware so I can add signatures:

blazescan -R

# Installation instruction

 ```git clone https://github.com/Hestat/lw-yara.git```

# scanning using clamav with custom rules

example at https://laskowski-tech.com/2018/04/26/eitest-cleanup-part-2-using-clamav-and-custom-yara-rules/


 ```clamscan -ir -l /root/scanresults.txt -d /root/lw-yara/lw-rules_index.yar -d /root/lw-yara/lw.hdb /path/to/scan/```

In clamscan 

```-ir flag will only report infected files and will scan recursively```

```-d flag allows you to specify a custom database, here we have 2 a hash database and a yara ruleset```

```-l creates a log of the scan```

***need to have clamav 98 or newer to parse Yara signatures***

More info here:

https://laskowski-tech.com/2018/05/17/malware-databased-custom-malware-signatures/


# Want a scanner to run this check out:

https://github.com/Hestat/blazescan


