rule phishing_actor_emails

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$a1= "bartr40@gmail.com"
	$a2= "james.bergkamp25@gmail.com"
	$a3= "bergkamp.james26@gmail.com"
	$a4= "wordpass487@gmail.com"
	$a5= "grisoy91@msn.com"
	$a6= "incoming@l3380.site"
	$a7= "chopdodo001@gmail.com"
	$a8= "mrlarrysss@gmail.com"
	$a9= "iyalaya00@gmail.com"
	$a10="fadawfaissal1@gmail.com"
	$a11="Rush3@live.ru"
	$a12="rezult1996@gmail.com"
	$a13="rezult277@gmail.com"

    condition:
    any of them
}
