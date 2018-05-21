rule ico_injection_detected
{

    meta:
       author = "Brian Laskowski"
       info = " general ico injection 05/18/18 "

    strings:
    
	$s1="<?php"
	$s2="@include"
	//$s3="ic\x6f"
	$s4="drupal_bootstrap"
	$s5="require_once"
	$s6="menu_execute_active_handler"

    condition:
    all of them
}

