/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_2

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig67 = "solevisible@gmail.com"
	$sig68 = "snichol@users.sourceforge.net"
	$sig70 = "singledana4000@gmail.com"
	$sig71 = "sing2tracey@gmail.com"
	$sig72 = "sheginst@gmail.com"
	$sig73 = "seroscho@googlemail.com"
	$sig75 = "serbanghita@gmail.com"
	$sig76 = "sebastian.goettschkes@googlemail.com"
	$sig78 = "sdcds5c4sd4c2020@gmail.com"
	$sig79 = "scottmatan@gmail.com"
	$sig80 = "scoreswin44@gmail.com"
	$sig81 = "schmittjoh@gmail.com"
	$sig82 = "sasia.result@gmail.com"
	$sig83 = "saifayachi9964@gmail.com"
	$sig84 = "sabas88@gmail.com"
	$sig85 = "s129800@hotmail.com"
	$sig86 = "rsjkingdom@gmail.com"
	$sig87 = "rs@dailymotion.com"
	$sig88 = "rphofsxrn@gmail.com"
	$sig89 = "rosemight63@gmail.com"
	$sig90 = "robinvsbatman2121@gmail.com"
	$sig91 = "rhondaa1000@gmail.com"
	$sig92 = "resultman27@gmail.com"
	$sig93 = "resultbox20@yandex.com"
	$sig94 = "replybox233@gmail.com"
	$sig96 = "rc50005000@zoho.com"
	$sig97 = "randyghayes@gmail.com"
	$sig98 = "py.stephane1@gmail.com"
	$sig99 = "pulzarraider@gmail.com"
	$sig100 = "psycholegzy@gmail.com"
	$sig101 = "proseskeylog6@gmail.com"
	$sig102 = "proofek@gmail.com"
	$sig104 = "pnlmmzqlf@yandex.com"
	$sig105 = "pleasedontdisablegmil@gmail.com"
	$sig106 = "pkwnicolas@gmail.com"
	$sig107 = "phishing@td.com"
	$sig108 = "phelipealvesdesouza@gmail.com"
	$sig110 = "paulstatezny@gmail.com"
	$sig111 = "patrickphlps@gmail.com"
	$sig112 = "password_test@test.com"
	$sig113 = "papaopama09@gmail.com"
	$sig114 = "pablolb@gmail.com"
	$sig115 = "pablo@users.sourceforge.net"
	$sig116 = "oneaboki@gmail.com"
	$sig117 = "oluxlamba@gmail.com"
	$sig118 = "office465@office.com"
	$sig119 = "octopussix6@gmail.com"
	$sig120 = "nulpunkt@gmail.com"
	$sig121 = "nouslagangresult@outlook.com"
	$sig122 = "nicolas.terrycartwrightsons@gmail.com"
	$sig123 = "nick.ilyin@gmail.com"
	$sig124 = "netmikey@gmail.com"
	$sig125 = "naydaluna32@gmail.com"
	$sig127 = "mtowers1953@gmail.com"

    condition:
    
	any of them
}

