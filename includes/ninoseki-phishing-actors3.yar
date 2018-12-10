/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_3

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig128 = "ms.userpc.ms@gmail.com"
	$sig129 = "mpriatel@rogers.com"
	$sig131 = "mohd.itcs@gmail.com"
	$sig132 = "mmarcy159@gmail.com"
	$sig133 = "mlehner@gmail.com"
	$sig134 = "mlady@users.sourceforge.net"
	$sig135 = "mjhsonn@gmail.com"
	$sig136 = "mithosmw@gmail.com"
	$sig137 = "middleeastresult@gmail.com"
	$sig138 = "michelsalib@hotmail.com"
	$sig139 = "michaltinka@gmail.com"
	$sig140 = "mialygk@gmail.com"
	$sig141 = "mhm5000@gmail.com"
	$sig142 = "medahnabil@gmail.com"
	$sig143 = "me@domain.com"
	$sig144 = "mbelinato@gmail.com"
	$sig145 = "matt.sturdy@gmail.com"
	$sig146 = "martin.hason@gmail.com"
	$sig147 = "manymen01@gmail.com"
	$sig148 = "mallluhuct@gmail.com"
	$sig149 = "major.ban221@gmail.com"
	$sig150 = "mahkhafx@gmail.com"
	$sig151 = "lw.l@hotmail.com"
	$sig152 = "love.struck092@gmail.com"
	$sig153 = "lookj9676@gmail.com"
	$sig154 = "logsmobb@mail.com"
	$sig156 = "linyaotsao@gmail.com"
	$sig157 = "linniksa@gmail.com"
	$sig158 = "lindamclean101111@gmail.com"
	$sig159 = "liebler.dominik@gmail.com"
	$sig160 = "leilapacha80@gmail.com"
	$sig161 = "legzyresult@zoho.com"
	$sig162 = "legzyresult@gmail.com"
	$sig163 = "legzyboss@mail.ru"
	$sig164 = "leeked@gmail.com"
	$sig165 = "lebron.james210101@gmail.com"
	$sig166 = "leafot@gmail.com"
	$sig167 = "lcastelli@gmail.com"
	$sig168 = "ktama.jwan@gmail.com"
	$sig169 = "kokosweet2018@gmail.com"
	$sig170 = "kingpawpaw1987@gmail.com"
	$sig171 = "kepten@gmail.com"
	$sig172 = "karlbaer2020@gmail.com"
	$sig173 = "kare.reith@gmail.com"
	$sig174 = "ka2ssx@gmail.com"
	$sig175 = "jsweat_php@yahoo.com"
	$sig176 = "jordan.alliot@gmail.com"
	$sig177 = "jonwage@gmail.com"
	$sig178 = "jonstones04@yandex.com"
	$sig179 = "jonstones04@gmail.com"
	$sig180 = "jonadabe@hotmail.com"
	$sig184 = "jmikola@gmail.com"
	$sig185 = "jlohwaterr@gmail.com"
	$sig187 = "jidemarvel1313@gmail.com"
	$sig188 = "jftp@joomla.org"
	$sig189 = "jelle.vink@gmail.com"
	$sig190 = "jeffarchey6@gmail.com"
	$sig191 = "jdebby06@gmail.com"
	$sig192 = "jaza.ali@gmail.com"

    condition:
    
	any of them
}
