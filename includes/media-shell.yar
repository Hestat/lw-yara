rule media_shell
{

    meta:
       author = "Brian Laskowski"
       info = " php shell 05/24/18 "

    strings:
    
	$s1="$pfile = $recover_file"
	$s2="$data = curl_exec"
	$s3="$gDir = str_replace"
	$s4="curl_close"
	$s5="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_"

    condition:
    all of them
}

