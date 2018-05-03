rule crypto_miner
{
	meta: 
	author= "Brian Laskowski"
	info= " Detected a cryptomining exe"

	strings:
		$miner = "stratum+tcp"
	
	condition:
		$miner
}

