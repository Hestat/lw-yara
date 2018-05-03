rule CPREA57_Webshell

{
        meta:
        author= "Brian Laskowski"
        info= " injection for tech support scam infrastructure"

        strings:
                $a = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); @eval( base64_decode("

                $b = "*947353*"
        condition:
                all of them
}

