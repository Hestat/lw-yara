/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-28
   Identifier: yertle
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule yertle_yertle {
   meta:
      description = "yertle - file yertle.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-28"
      hash1 = "2031cea1ee6be78abc632b7be0b4ef3c180da44d601348543db408b68b0ec4d6"
   strings:
      $s1 = "// Copied and modified from https://github.com/leonjza/wordpress-shell" fullword ascii
      $s2 = "Author URI: https://github.com/n00py" fullword ascii
      $s3 = "Description: This is a backdoor PHP shell designed to be used with the Yertle script from WPForce." fullword ascii
      $s4 = "Plugin URI: https://github.com/n00py" fullword ascii
      $s5 = "$command = substr($command, 0, -1);" fullword ascii
      $s6 = "Plugin Name: Yertle Interactive Shell" fullword ascii
      $s7 = "call_user_func_array('system', array($command));" fullword ascii
      $s8 = "$command = base64_decode($command);" fullword ascii
      $s9 = "call_user_func('system', $command);" fullword ascii
      $s10 = "$command = $_GET[\"cmd\"];" fullword ascii
      $s11 = "system($command);" fullword ascii
      $s12 = "$thingy = $function->invoke($command );" fullword ascii
      $s13 = "$function = new ReflectionFunction('system');" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 2KB and
         ( 8 of them )
      ) or ( all of them )
}

rule yertle_r {
   meta:
      description = "yertle - file yertle-r.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-28"
      hash1 = "527d3b0ede0780c48098c4bd43c266ca91c6bd417c7144ef898fa1326292130b"
   strings:
      $s1 = "$shell = 'uname -a; w; id; python -c \\'import pty;pty.spawn(\"/bin/bash\")\\'';" fullword ascii
      $s2 = "// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck." fullword ascii
      $s3 = "Description: This spawns a backdoor PHP reverse shell designed to be used with the Yertle script from WPForce." fullword ascii
      $s4 = "// This script will make an outbound TCP connection to a hardcoded IP and port." fullword ascii
      $s5 = "printit(\"ERROR: Shell process terminated\");" fullword ascii
      $s6 = "// php-reverse-shell - A Reverse Shell implementation in PHP" fullword ascii
      $s7 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s8 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
      $s9 = "// Spawn shell process" fullword ascii
      $s10 = "// The recipient will be given a shell running as the current user (apache normally)." fullword ascii
      $s11 = "Author URI: https://github.com/n00py" fullword ascii
      $s12 = "printit(\"ERROR: Shell connection terminated\");" fullword ascii
      $s13 = "// Make the current process a session leader" fullword ascii
      $s14 = "// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows." fullword ascii
      $s15 = "0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from" fullword ascii
      $s16 = "// This tool may be used for legal purposes only.  Users take full responsibility" fullword ascii
      $s17 = "Plugin URI: https://github.com/n00py" fullword ascii
      $s18 = "Plugin Name: Yertle Reverse Shell" fullword ascii
      $s19 = "// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available." fullword ascii
      $s20 = "printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}

rule leonjzashell {
   meta:
      description = "yertle - file leonjzashell.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-28"
      hash1 = "5f01b6d93673c9d1673aea513c51688b54e1c8c5c31e9770f6530c4dfdbc87dd"
   strings:
      $x1 = "Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugi" fullword ascii
      $x2 = "Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugins/s" ascii
      $s3 = "ns/shell/shell.php. Commands can be given using the 'cmd' GET parameter. Eg: \"http://192.168.0.1/wp-content/plugins/shell/shell" ascii
      $s4 = "Plugin URI: https://github.com/leonjza/wordpress-shell" fullword ascii
      $s5 = "# grab the command we want to run from the 'cmd' GET parameter" fullword ascii
      $s6 = "# Try to find a way to run our command using various PHP internals" fullword ascii
      $s7 = "# http://php.net/manual/en/function.system.php" fullword ascii
      $s8 = "php?cmd=id\", should provide you with output such as <code>uid=33(www-data) gid=verd33(www-data) groups=33(www-data)</code>" fullword ascii
      $s9 = "# http://php.net/manual/en/function.call-user-func-array.php" fullword ascii
      $s10 = "call_user_func_array('system', array($command));" fullword ascii
      $s11 = "# attempt to protect myself from deletion" fullword ascii
      $s12 = "# http://php.net/manual/en/function.call-user-func.php" fullword ascii
      $s13 = "call_user_func('system', $command);" fullword ascii
      $s14 = "$command = $_GET[\"cmd\"];" fullword ascii
      $s15 = "Plugin Name: Cheap & Nasty Wordpress Shell" fullword ascii
      $s16 = "system($command);" fullword ascii
      $s17 = "# http://php.net/manual/en/class.reflectionfunction.php" fullword ascii
      $s18 = "# has system() on a blacklist anyways :>" fullword ascii
      $s19 = "$function->invoke($command);" fullword ascii
      $s20 = "Author URI: https://leonjza.github.io" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 4KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

