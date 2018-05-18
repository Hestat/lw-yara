rule alfa_perl_shell
{

    meta:
       author = "Brian Laskowski"
       info = " alfa perl webshell 05/17/18 "

    strings:
    
	$s3="ExecuteCommand"	

    condition:
    all of them
}

