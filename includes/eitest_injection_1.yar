rule eitest_injection_1

{

	meta:
	 author= "Brian Laskowski"
	 date= "4/25/18"
	 description= "eitest malware injection"
	strings:
	 $a= "bubE"
	 $b= "?php"
	 $c= "explode(chr"
	condition:
	all of them
}

