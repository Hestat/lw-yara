rule generic_php_obfuscated_shell

{

	meta:
	 author= "Brian Laskowski"
	 date= "5/21/18"
	 description= "general php malware with obfuscation"
	strings:
	
	$s1="auth_pass"
	$s2="function"
	$s3="strlen"
	$s4="return"
	$s5="?php"
	$s6="base64_decode"


	condition:
	all of them
}

