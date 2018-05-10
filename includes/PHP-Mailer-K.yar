rule PHP_Mailer_K

{
        meta:
        author= "Brian Laskowski"
        info= " php mailer sighted 05/10/18 https://www.virustotal.com/#/file/8144d69d27f0b5c209d6d7a995cc31e1ff0cdc341fc3b266938979947ac06cb2/detection "

        strings:
		$a= "urlencode($message)"
		$b= "urldecode($message)"
		$c= "stripslashes($message)"
		$d= "$email = explode"
		$e= "while($email[$i]"
		$f= "alert"
 

        condition:
                all of them
}

