rule dark_shell
{

    meta:
       author = "Brian Laskowski"
       info = " darkshell 05/24/18 "

    strings:
    
	$s1="$items = scandir ($file)"
	$s2="$range = explode"
	$s3="case 'port_scan'"
	$s4="if(move_uploaded_file($temp,$file))"

    condition:
    all of them
}

