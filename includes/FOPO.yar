rule FOPOobfuscator
{
	meta: 
	author= "Brian Laskowski"
	info= " FOPO Obfuscator detected"

	strings:
		$fopo = "Obfuscation provided by FOPO"
	
	condition:
		$fopo
}
