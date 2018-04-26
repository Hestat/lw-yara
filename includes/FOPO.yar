rule FOPOobfuscator
{
	meta: 
	author= "Hestat"
	info= " FOPO Obfuscator detected"

	strings:
		$fopo = "Obfuscation provided by FOPO"
	
	condition:
		$fopo
}
