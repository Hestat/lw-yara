rule data_chaos_backdoor_shell
{

    meta:
       author = "Brian Laskowski"
       info = " perl backdoor shell 05/21/18 "

    strings:
    
	$s1="/usr/bin/perl"
	$s2="Data Cha0s Connect Back Backdoor"
	$s3="use Socket"

    condition:
    all of them
}

