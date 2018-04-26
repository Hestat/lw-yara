rule crypto_miner
{
	meta: 
	author= "Hestat"
	info= " Detected a cryptomining exe"

	strings:
		$miner = "stratum+tcp"
	
	condition:
		$miner
}

