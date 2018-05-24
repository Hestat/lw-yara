rule wordpress2_ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/21/18 "

    strings:
    
	$s1="<?php"
	$s2="Front to the WordPress application"
	$s3="@include"
	//$s4="ic\x6f"

    condition:
    all of them and filesize < 20KB
}

