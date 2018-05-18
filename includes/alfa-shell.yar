rule alfa_webshell
{

    meta:
       author = "Brian Laskowski"
       info = " general php injection 05/16/18 "

    strings:
    
    	$s1="Alfa_User"
    	$s2="Alfa_Pass"
	$s3="Alfa_Protect_Shell"

    condition:
    all of them
}

