// implemented WORDFENCE RULES from the following whitepaper writeup:
// https://www.wordfence.com/wp-content/uploads/2018/06/Wordfence-BabaYaga-WhitePaper.pdf
//

rule WFYARAGEN_G4129_rules_1
{
	meta:

	description = "Malicious code meant to look like WordPress core"
	
	strings:

	$re = /\@include\s*\(\s*ABSPATH\s*\.\s*WPINC\s*\.\s*['"]\/Requests\/IPconfig\.ini['"]/ nocase

	condition:
	$re

}

rule WFYARAGEN_G4290_rules_1
{

	meta:

	description = "Matches a URL-encoded string with magic bytes fitting a zlib stream"

	strings:
	$re = /^x\%(?:01|25|9C|DA|5E)[\%A-Za-z\d\.\-\+\_]+$/ nocase

	condition:
	$re
}

rule WFYARAGEN_G4361_rules_1
{
	meta:

	description = "Unique enough typo found in some of the backdoor code"

	strings:

	$re = /usecloack/ nocase

	condition:
	$re
}

rule WFYARAGEN_G4399_rules_1
{
	meta:

	description = "Not relying on the typo to detect the backdoor here"

	strings:
	$re =/\$(?P<var>[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\=\s*md5\s*\(\s*__FILE__\s*\)\s*\;[\s\S]{1,500}?=\s*['"]ke['"]\s*\.\s*\$(?P=var)\s*\.\s*['"]ys['"]\s*\;[^=]+\=\s*['"]use['"]\s*\.\s*\$(?P=var)\s*\.\s*['"]ragents/ nocase

	condition:
	$re
}


rule WFYARAGEN_G45_rules_2
{
	meta:

	description = "Catches generic backdoor - setting an option"

	strings:
	$re = /\$home_cwd\s*+=\s*+@getcwd\s*+\(\s*+\)\s*+;\s*+if\s*+\(\s*+isset\s*+\(\s*+\$_POST\s*+\[\s*+['"]\w{1,10}\s*+['"]\s*+\]\s*+\)\s*+\)\s*+@chdir\s*+\(\s*+\$_POST\s*+\[\s*+['"]\w{1,10}['"]\s*+\]\s*+\)\s*+;\s*+\$cwd\s*+=\s*+@getcwd\s*+\(\s*+\)\s*+;\s*+if\s*+\(\s*+\$os\s*+==\s*+['"]\s*+win\s*+['"]\s*+\)/ nocase

	condition:
	$re
}


rule WFYARAGEN_G1535_rules_2
{
	meta:
	description = "Obfuscated eval-gzinflate"

	strings:
	$re = /@\$\w+\s*?=\s*?"\s*?e\\x76\\x61l\s*?\(\s*?\\x67\\x7Ai\\x6E\\x66\\x6C\\x61t\\x65\s*?\(/ nocase

	condition:
	$re
}

rule WFYARAGEN_G1832_rules_3
{
	meta:

	description = "Matches file used in various infections"

	strings:

	$re = /^0\.5\.2\.2\s*?0\.83\.4\.1\s+?1\.0\.145\.2\s+?1\.0\.145\.210\s+?1\.0\.177\.126/ nocase

	condition:
	$re
}

rule WFYARAGEN_G736_rules_8
{

	meta:

	description = "Matches backdoor found in infections - assert-eval"

	strings:

	$re = /if\s*\(\s*\w{1,255}\s*\(\$_(?:REQUEST|GET|POST|COOKIE)\s*\[\s*'\s*\w{1,255}\s*'\s*\]\s*\)\s*\)\s*\w{1,255}\s*\(\s*stripslashes\s*\(\s*\$_(?:REQUEST|GET|POST|COOKIE)\s*\[\s*bot\s*\]\s*\)\s*\)\s*;/ nocase

	condition:
	$re
}

rule WFYARAGEN_G736_rules_9
{

	meta:
	description = "Part of malware, basic backwards obfuscation"

	strings:

	$re = /strrev\s*\(\s*['"]\s*=ecruos&wordpress\?\/moc\.yadot-syasse\/\/:ptth\s*['"]\s*\)\s*;/ nocase

	condition:
	$re
}

rule WFYARAGEN_G4304_rules_1
{

	meta:
	
	description = "htaccess rule used to limit access to pages"

	strings:

	$re = /RewriteCond \%\{HTTP_USER_AGENT\}\!en\.support\.wordpress\.com\s+RewriteRule \.\* \- \[R=404\]/ nocase

	condition:
	$re
}

rule WFYARAGEN_G4472_rules_1
{

	meta:

	description = "Double-var fn around base64 string"

	strings:

	$re = /\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*['"][A-Za-z\d\/\+]+=*['"]\s*\)/

	condition:
	$re
}
