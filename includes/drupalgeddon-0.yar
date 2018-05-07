rule drupal_CVE_2018_7600_RCE_0
{
	meta: 
	author= "Brian Laskowski"
	info= " Drupal RCE shell"

	strings:
		$a = "echo"
		$b = "<pre>"
		$c = ";system($_GET['c'])"
	
	condition:
		all of them
}

