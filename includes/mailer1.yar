rule mailer1
{

	meta:
	   author = "Hestat"
	   info = " php mailer script "

	strings:
	
	$s1="$_COOKIE [str_replace('.', '_', $_SERVER['HTTP_HOST'])])"

	condition:
	all of them
}
