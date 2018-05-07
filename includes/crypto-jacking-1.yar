rule bad_packets_crypto_jacking_1
{
	meta: 
	author= "Brian Laskowski"
	info= " https://badpackets.net/large-cryptojacking-campaign-targeting-vulnerable-drupal-websites/ "

	strings:
		$a = "var dZ1= window"
		$b = "var ZBRnO2= window"
	
	condition:
		all of them
}

