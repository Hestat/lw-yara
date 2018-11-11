/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_8

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig449 = "kiank@secure.eg.co.uk"
	$sig450 = "kontakt@beberlei.de"
	$sig451 = "kris@symfony.com"
	$sig452 = "lalala@lala.co"
	$sig453 = "lalala@lala.com"
	$sig454 = "lars@usenet.noschinski.de"
	$sig455 = "legzy@schoolofhacking.com"
	$sig456 = "legzyresult@excite.com"
	$sig457 = "lenar@city.ee"
	$sig458 = "leonard@acm.org"
	$sig459 = "liqwei@liqwei.com"
	$sig460 = "logs@l4rg3.com"
	$sig461 = "lucas@lucasguimaraes.com"
	$sig462 = "lyrixx@lyrixx.info"
	$sig463 = "mail@mail0.emidhost.com.br"
	$sig464 = "mail@milianw.de"
	$sig465 = "maillog@log.org"
	$sig466 = "marc@marc-abramowitz.com"
	$sig467 = "marc@pedigital.de"
	$sig468 = "marcorighi@tchesoft.com"
	$sig469 = "mark@moderndeveloperllc.com"
	$sig470 = "mark@swiftmailer.org"
	$sig471 = "markus.bachmann@bachi.biz"
	$sig472 = "masxy@foxmail.com"
	$sig473 = "matthew@lewinski.org"
	$sig474 = "me@stichoza.com"
	$sig475 = "mic@rezlt.org"
	$sig476 = "michael.williams@funsational.com"
	$sig477 = "mike@graftonhall.co.nz"
	$sig478 = "mingo@rotedic.com"
	$sig479 = "monte@ispi.net"
	$sig480 = "monte@ohrt.com"
	$sig481 = "moore@cs.utk.edu"
	$sig482 = "mrprofessor@jodo.im"
	$sig483 = "mso@phlylabs.de"
	$sig484 = "my.other@address.com"
	$sig485 = "n@boxs.com"
	$sig486 = "naderman@naderman.de"
	$sig487 = "nawawi@rutweb.com"
	$sig488 = "newline@vandyke.com"
	$sig489 = "newsupdate@pdf.com"
	$sig490 = "newsupdate@servicedropbox.com"
	$sig491 = "newsupdate@servisdropbox.com"
	$sig492 = "nicholas@dionysopoulos.me"
	$sig493 = "niklas.fiekas@tu-clausthal.de"
	$sig494 = "noreply@cssv.com"
	$sig495 = "noreply@idyat.com"
	$sig496 = "noreply@logs.com"
	$sig497 = "noreply@vssv.com"
	$sig498 = "o@42mm.org"
	$sig499 = "other@domain.org"
	$sig500 = "outgoing@l3380.site"
	$sig501 = "p@tchwork.com"
	$sig502 = "pagez@l33bo.website"
	$sig503 = "paulo@controllerweb.com.br"
	$sig504 = "petrich@tronic-media.com"
	$sig505 = "phishingfarm@rows.io"
	$sig506 = "php@live.fr"
	$sig507 = "phpmailer@synchromedia.co.uk"
	$sig508 = "pierre.minnieur@sensiolabs.de"
	$sig509 = "pm@datasphere.ch"
	$sig510 = "powered@hex.id"
	$sig511 = "pp@pp.s-tampan.com"
	$sig512 = "przemek@sobstel.org"

    condition:
    
	any of them
}

