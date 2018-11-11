/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_5

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig257 = "dserruyaconsultng@gmail.com"
	$sig258 = "dr.cole15@gmail.com"
	$sig259 = "dp@yandex.ru"
	$sig260 = "donatorouco@gmail.com"
	$sig261 = "doc@docusig262n.com"
	$sig263 = "doc@adobe.com"
	$sig264 = "dirklgardner@gmail.com"
	$sig265 = "decanneresult@gmail.com"
	$sig266 = "ddobervich@gmail.com"
	$sig267 = "dcsdcdsdsc020@gmail.com"
	$sig268 = "davederek30@gmail.com"
	$sig269 = "darek.krk@gmail.com"
	$sig270 = "customercare.peoplemeet90809@gmail.com"
	$sig271 = "cushlilly@yahoo.com"
	$sig272 = "copghost@yahoo.com.br"
	$sig273 = "copghodst@yahoo.com.br"
	$sig274 = "coolbru@users.sourceforge.net"
	$sig275 = "constancejane22@gmail.com"
	$sig276 = "codeworxtech@users.sourceforge.net"
	$sig277 = "chuck@horde.org"
	$sig278 = "christiangaertner.film@googl	$sig279 = .com"
	$sig280 = "chris@example.com"
	$sig281 = "chevrecruitmentteam@gmail.com"
	$sig282 = "cecep.prawiro@gmail.com"
	$sig283 = "cc@example.com"
	$sig284 = "cbergau86@gmail.com"
	$sig285 = "catalin@dazoot.ro"
	$sig286 = "bugattig12@gmail.com"
	$sig287 = "bschussek@gmail.com"
	$sig288 = "brahimtlm302@gmail.com"
	$sig289 = "box@adobe.com"
	$sig290 = "bob@aol.com"
	$sig291 = "bnkforms@gmail.com"
	$sig292 = "blessingresults@gmail.com"
	$sig293 = "beboofficedesk@gmail.com"
	$sig294 = "bcc@example.org"
	$sig295 = "bcc@example.com"
	$sig296 = "barryvdh@gmail.com"
	$sig297 = "bantu@phpbb.com"
	$sig298 = "bahjat983@hotmail.com"
	$sig299 = "azizjeu@yahoo.com"
	$sig300 = "azizdalirezlt@gmail.com"
	$sig301 = "ayoolashola110@gmail.com"
	$sig302 = "authenticatestreams@gmail.com"
	$sig303 = "athenalightenedmypath@gmail.com"
	$sig304 = "atendimento.site@magazineluiza.com.br"
	$sig305 = "arvindlease@gmail.com"
	$sig306 = "arnaud.lb@gmail.com"
	$sig307 = "arezultat2014@gmail.com"
	$sig308 = "aqilnaila23@gmail.com"
	$sig309 = "any@example.org"
	$sig310 = "another@domain.com"
	$sig311 = "anonplus2k17@godaddy.com"
	$sig312 = "annmahan45@gmail.com"
	$sig313 = "aniekan.donking3@gmail.com"
	$sig314 = "amato0617@gmail.com"
	$sig315 = "alleduorofficejob@yandex.com"
	$sig316 = "alishakeary01@gmail.com"
	$sig317 = "alibabaorg23@gmail.com"
	$sig318 = "alexandre.salome@gmail.com"
	$sig319 = "alexander.merz@web.de"
	$sig320 = "alecz.fia@gmail.com"

    condition:
    
	any of them
}

