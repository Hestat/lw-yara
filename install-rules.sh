#initialize
sleep 1
echo "This tool will added LW yara rules to your maldect configuration to improve malware scans"
sleep 1

if [[ -x $(which maldet) ]] 2> /dev/null; then #maldet installed

	#backup existing rules
	cp -av /usr/local/maldetect/sigs/rfxn.yara{,.bak}
	#add combined ruleset
	cat lw-rules-combined.yar >> /usr/local/maldetect/sigs/rfxn.yara
	echo " Backed up existing rules to"
	echo "/usr/local/maldetect/sigs/rfxn.yara.bak"
	echo "Good Hunting!"

else 
	echo "maldet is not installed please install maldet first"

fi
