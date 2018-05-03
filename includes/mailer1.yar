rule php_mailer_1
{

	meta:
	   author = "Brian Laskowski"
	   info = " php mailer script "

	strings:
	
	$s1="$_COOKIE [str_replace('.', '_', $_SERVER['HTTP_HOST'])])"

	condition:
	all of them
}
