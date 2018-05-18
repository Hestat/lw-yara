rule generic_php_injection_2
{

    meta:
       author = "Brian Laskowski"
       info = " general php injection 05/16/18 "

    strings:
    
    	$s1="if"
	$s2="isset"
	$s3="$_REQUEST"
	$s4="eval"

    condition:
    	all of them and filesize < 20KB
    
}

