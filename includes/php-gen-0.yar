rule generic_php_injection_0
{

    meta:
       author = "Brian Laskowski"
       info = " drupal injection "

    strings:
    
    $s1="$GLOBALS"
    $s2="Array();global"
    $s3="eval"
    $s4="NULL"

    condition:
    all of them
}
