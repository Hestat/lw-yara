rule wordpress0_ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/21/18 "

    strings:
    
	$s1="<?php"
	$s2="Front to the WordPress application"
	$s3="@ini_set(\"error_log\",NULL)"
	$s4="assert_options"

    condition:
    all of them
}

