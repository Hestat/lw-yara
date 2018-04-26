rule cache_mailer
{

	meta:
	   author = "Brian Laskowski"
	   info = " php mailer script "

	strings:
	
	$s1="if (mail(stripslashes(base64_decode($fr[0]))"

	condition:
	all of them
}

rule cache_mailer_encoded_1
{

	meta:
	  author = "Brian Laskowski"
	  info = " obfuscated php shell "

	strings:

	$s1="pod_h1kgzu0cqr"

	condition:
	all of them
}
rule eitest_injection_0

{

	meta:
	 author= "Brian Laskowski"
	 date= "4/25/18"
	 description= "eitest malware injection"
	strings:
	 $a= "@error_reporting(0)"
	 $b= "!isset($eva1f"
	condition:
	all of them
}
rule eitest_injection_1

{

	meta:
	 author= "Brian Laskowski"
	 date= "4/25/18"
	 description= "eitest malware injection"
	strings:
	 $a= "bubE"
	 $b= "?php"
	condition:
	all of them
}
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
rule php_mailer_1
{

	meta:
	   author = "Brian Laskowski"
	   info = " php mailer script "

	strings:
	
	$s1="$_COOKIE [str_replace('.', '_', $_SERVER['HTTP_HOST'])])"

	condition:
	all of them
}
rule crypto_miner
{
	meta: 
	author= "Brian Laskowski"
	info= " Detected a cryptomining exe"

	strings:
		$miner = "stratum+tcp"
	
	condition:
		$miner
}

/*
    I first found this in May 2016, appeared in every PHP file on the
    server, cleaned it with `sed` and regex magic. Second time was
    in June 2016, same decoded content, different encoding/naming.
    https://www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99
*/
rule php_anuna_eitest
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a PHP Trojan"
    strings:
        $a = /<\?php \$[a-z]+ = '/
        $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
        $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
        $d = /if \(!function_exists\('[a-z]+'\)\)/
    condition:
        all of them
}

