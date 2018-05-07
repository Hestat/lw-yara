# lw-yara

Yara rulset based on php shells and other webserver malware. 

# scanning using clamav with custom rules

example at https://laskowski-tech.com/2018/04/26/eitest-cleanup-part-2-using-clamav-and-custom-yara-rules/


 ```clamscan -ir -d /root/lw-yara/lw-rules-combined.yar /path/to/scan/```




# This is still work in progress

Includes an install script to allow for the rules to be added to the maldet scanner.

https://github.com/rfxn/linux-malware-detect

https://www.rfxn.com/projects/linux-malware-detect/

Can be used indepentent of maldet if yara is already installed.

To add to maldet run the install-rules.sh script.
