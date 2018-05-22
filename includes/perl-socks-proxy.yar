rule perl_socks_proxy
{

    meta:
       author = "Brian Laskowski"
       info = " perl socks proxy 05/21/18 "

    strings:
    
	$s1="/usr/bin/perl"
	$s2="socks_bind"
	$s3="socks_connect"
	$s4="socks_do"

    condition:
    all of them
}

