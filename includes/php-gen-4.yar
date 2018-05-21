rule generic_php_obfuscated_shell_01

{

	meta:
	 author= "Brian Laskowski"
	 date= "5/21/18"
	 description= "general php malware with obfuscation"
	strings:
	
	$s1="?php"
	$s2="eval"
	$s3="intval"
	$s4="str_replace"
	$s5="gzinflate"
	$s6="base64_decode"

	condition:
	all of them
}

