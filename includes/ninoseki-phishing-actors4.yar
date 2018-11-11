/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_4

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig193 = "ircmaxell@php.net"
	$sig194 = "info_receiver@gmail.com"
	$sig195 = "imprec@gmail.com"
	$sig196 = "igormagazine2017@gmail.com"
	$sig197 = "icon@linux.duke.edu"
	$sig198 = "ibrahim.mekily@gmail.com"
	$sig199 = "iamjiboss2013@gmail.com"
	$sig200 = "iam.asm89@gmail.com"
	$sig201 = "ialzm86@gmail.com"
	$sig202 = "hutchinsteve@gmail.com"
	$sig203 = "huseyinyazici777@gmail.com"
	$sig204 = "hrvoj3e@gmail.com"
	$sig205 = "hlreurope@gmail.com"
	$sig206 = "harryseeksyou460@gmail.com"
	$sig207 = "harijbe88@gmail.com"
	$sig208 = "hackangelnelly511@yandex.com"
	$sig209 = "habdel707@gmail.com"
	$sig210 = "guilhermeblanco@hotmail.com"
	$sig211 = "gregphisper1@gmail.com"
	$sig212 = "greggfrazierr@gmail.com"
	$sig213 = "grea48843@gmail.com"
	$sig214 = "gopro3903@gmail.com"
	$sig215 = "goodvbesk2@gmail.com"
	$sig216 = "goldentail75@gmail.com"
	$sig217 = "godsonresult@gmail.com"
	$sig218 = "god@example.com"
	$sig219 = "gildas.quemener@gmail.com"
	$sig220 = "geoffers@gmail.com"
	$sig221 = "general@lists.sourceforge.net"
	$sig222 = "freshresults2014@gmail.com"
	$sig223 = "frankiedallas7@gmail.com"
	$sig224 = "fozywire114@gmail.com"
	$sig225 = "fm.majestyint@gmail.com"
	$sig226 = "feminist008@gmail.com"
	$sig227 = "fco_ernesto@yahoo.com.br"
	$sig228 = "faha1ad2@hotmail.com"
	$sig229 = "fabiobeneditto@gmail.com"
	$sig230 = "fabien@example.com"
	$sig231 = "fabien.potencier@gmail.com"
	$sig232 = "example@example.com"
	$sig233 = "ever.zet@gmail.com"
	$sig234 = "eric@thumbtack.com"
	$sig235 = "emailcenter@newsletter.magazineluiza.com.br"
	$sig237 = "emailcenter2@newsletter.magazineluiza.com.br"
	$sig254 = "elimart.bookz@gmail.com"
	$sig255 = "ejramhrb@gmail.com"
	$sig256 = "dunglas@gmail.com"

    condition:
    
	any of them
}
