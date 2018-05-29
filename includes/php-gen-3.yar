rule generic_php_03

{

	meta:
	 author= "Brian Laskowski"
	 date= "5/29/18"
	 description= "example.sites.php malware"
	strings:
	$a= "function_exists"
	$b= "function"
	$c= "for"
	$d= "xor"
	$e= "chr"
	$f= "strlen"
	$g= "return"
	$h= "=array"
	$i= "?php"

	condition:
	all of them
}
