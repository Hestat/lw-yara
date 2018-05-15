rule phishing_actor_emails

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$a1= "bartr40@gmail.com"
	$a2= "james.bergkamp25@gmail.com"
	$a3= "bergkamp.james26@gmail.com"

    condition:
    any of them
}
