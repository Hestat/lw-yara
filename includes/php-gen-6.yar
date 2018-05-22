rule generic_php_shell_2
{

    meta:
       author = "Brian Laskowski"
       info = " generic php shell exec 05/22/18 "

    strings:
    
	$s1="?php"
	$s2="if"
	$s3="isset"
	$s4="_REQUEST"
	$s5="eval"
	$s6="exit"

    condition:
    all of them
}

