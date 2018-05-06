rule crypto_miner_config_file_0
{
	meta: 
	author= "Brian Laskowski"
	info= " Detected a cryptomining config file"

	strings:
		$m = "pool_address"
		$m1 = "wallet_address"
		$m2 = "pool_password"
		$m3 = "pool_weight"
	
	condition:
		all of them
}

