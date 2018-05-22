rule generic_php_upload_shell_1
{

    meta:
       author = "Brian Laskowski"
       info = " obfuscated php upload shell 05/22/18 "

    strings:
    
	$s1="?php"
	$s2="@error_reporting(0)"
	$s3="@eval"
	$s4="base64_decode"

    condition:
    all of them
}

