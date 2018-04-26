rule cachemailer
{

	meta:
	   author = "Hestat"
	   info = " php mailer script "

	strings:
	
	$s1="if (mail(stripslashes(base64_decode($fr[0]))"

	condition:
	all of them
}

rule cachmailerencoded1
{

	meta:
	  author = "Hestat"
	  info = " obfuscated php shell "

	strings:

	$s1="pod_h1kgzu0cqr"

	condition:
	all of them
}
