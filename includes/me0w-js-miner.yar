rule meow_js_miner
{

    meta:
       author = "Brian Laskowski"
       info = " meow.js cryptominer 05/17/18 "

    strings:
    
   	$s1="data"
	$s7="application/octet-stream"
	$s8="base64"
	$s2="hashsolved"  
	$s3="k.identifier" 
	$s4="acceptedhashes"
	$s5="eth-pocket"
	$s6="8585"

    condition:
    all of them
}

