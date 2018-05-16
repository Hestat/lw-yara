rule generic_php_injection_1
{

    meta:
       author = "Brian Laskowski"
       info = " general php injection 05/16/18 "

    strings:
    
    $s1="Array()"
    $s2="foreach"
    $s3="eval"
    $s4="($_COOKIE, $_POST)"
    $s5="exit()"
    $s6="function"
    $s7="<?php"
    $s8="return"

    condition:
    all of them
}

