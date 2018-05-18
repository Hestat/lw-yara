rule ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/18/18 "

    strings:
    
	$s1="<?php"
	$s2="@include"
	$s3="ic\x6f"

    condition:
    all of them
}

