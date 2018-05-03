rule cache_mailer
{

	meta:
	   author = "Brian Laskowski"
	   info = " php mailer script "

	strings:
	
	$s1="if (mail(stripslashes(base64_decode($fr[0]))"

	condition:
	all of them
}

rule cache_mailer_encoded_1
{

	meta:
	  author = "Brian Laskowski"
	  info = " obfuscated php shell "

	strings:

	$s1="pod_h1kgzu0cqr"

	condition:
	all of them
}
