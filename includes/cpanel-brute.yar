rule cpanel_brute_force_tool_brutus
{

    meta:
       author = "Brian Laskowski"
       info = " cpanel brute force tool 05-14-18 "

    strings:
  	$a= "$password=array_unique"
	$b= "$username=array_unique"
	$c= "$start=time"
	$d= "explode"

    condition:
    all of them
}

