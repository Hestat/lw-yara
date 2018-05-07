rule bad_packets_crypto_jacking_0
{
	meta: 
	author= "Brian Laskowski"
	info= " https://badpackets.net/large-cryptojacking-campaign-targeting-vulnerable-drupal-websites/ "

	strings:
		$a = "var RqLm1=window"
		$b = "var D2=window"
	
	condition:
		all of them
}

