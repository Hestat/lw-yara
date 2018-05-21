PWD=$(pwd)

#initialize
sleep 1
echo "This tool will added LW yara rules to your maldect configuration to improve malware scans"
sleep 1

if [[ -x $(which maldet) ]] 2> /dev/null; then #maldet installed

	#backup existing rules
	cp -av /usr/local/maldetect/sigs/rfxn.yara{,.bak}
	cp -av $PWD/lw-rules_index.yar /usr/local/maldetect/sigs/
	cp -av $PWD/includes /usr/local/maldetect/sigs/includes
	#add combined ruleset
	sed -i s/"sigdir\/rfxn.yara"/"sigdir\/lw-rules_index.yar"/g /usr/local/maldetect/internals/internals.conf
	#for i in $(cut -d '"' -f 2 lw-rules_index.yar); do cat $i >>  /usr/local/maldetect/sigs/rfxn.yara; done
	#cat lw-rules-combined.yar >> /usr/local/maldetect/sigs/rfxn.yara
	echo " Backed up existing rules to"
	echo "/usr/local/maldetect/sigs/rfxn.yara.bak"
	echo "Good Hunting!"

else 
	echo "maldet is not installed please install maldet first"

fi
