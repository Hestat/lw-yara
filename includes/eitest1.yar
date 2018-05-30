rule eitest_injection_0

{

	meta:
	 author= "Brian Laskowski"
	 date= "4/25/18"
	 description= "eitest malware injection"
	strings:
	 $a= "@error_reporting(0)"
	 $b= "!isset($eva1f"
	 $c= "?php"
	condition:
	all of them
}
