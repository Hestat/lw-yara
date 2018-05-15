rule phishing_well_fargo

{

    meta:
       author = "Brian Laskowski"
       info = " wells fargo phishing kit "

    strings:
    
	$a= "$formproc_obj"
	$b= "$data_email_sender"
	$c= "$validator"
	$d= "/templ/wells_email_subj.txt"

    condition:
    all of them
}

