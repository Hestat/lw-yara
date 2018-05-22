rule rfi_perl_bot
{

    meta:
       author = "Brian Laskowski"
       info = " rfi perl bot 05/21/18 "

    strings:
    
	$s1="/usr/bin/perl"
	$s2="RFI Scanner Bot"
	$s3="FeeLCoMz"

    condition:
    all of them
}

