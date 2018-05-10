rule CPR4616_Webshell

{
        meta:
        author= "Brian Laskowski"
        info= " php webshell sighted 05/10/18 https://www.virustotal.com/#/file/266ae931e817c701fd4098d37edfdfcc814a02e0820f72c659e0c11f6e2cf070/detection "

        strings:
		$a= "$auth_pass ="
		$b= "$eval=("
		$c= ".gzuncompress(base64_decode"
		$d= "?php"
		$e= "?>"

        condition:
                all of them
}

