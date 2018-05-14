rule symlink_hacking_tool
{

    meta:
       author = "Brian Laskowski"
       info = " symlink hack tool 05-14-18 "

    strings:
    	
	$a= "$folfig"
	$b= "$str=explode"
	$c= "$home"
	$d= "$user"
	$e= "symlink"

    condition:
    all of them
}
