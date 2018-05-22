rule alfa_perl_shell
{

    meta:
       author = "Brian Laskowski"
       info = " alfa perl webshell 05/17/18 "

    strings:
    
	$s1="usr/bin/perl"
	$s2="$WinNT"
	$s3="ExecuteCommand"
	$s4="Killed it!"
	

    condition:
    all of them
}

