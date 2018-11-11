/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_9

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig513 = "rafael@doh.ms"
	$sig514 = "rafael@tchesoft.com"
	$sig515 = "receiver@domain.org"
	$sig516 = "redcoca@protonmail.com"
	$sig517 = "replace@this.com"
	$sig518 = "resultz@boss.com"
	$sig519 = "rich@corephp.co.uk"
	$sig520 = "richardc@unixbeard.net"
	$sig521 = "rob@irongaze.com"
	$sig522 = "roberto@berto.net"
	$sig523 = "rok3@rok3.me"
	$sig524 = "roman@code-factory.org"
	$sig525 = "ronny@hoojima.com"
	$sig526 = "ryan@wonko.com"
	$sig527 = "s.stok@rollerscapes.net"
	$sig528 = "scst@php-tools.net"
	$sig529 = "sdafasdfasf@adsf.com"
	$sig530 = "sempakcrew@mail.id"
	$sig531 = "service@credit.fr"
	$sig532 = "seu@	$sig533 = .com"
	$sig534 = "sm@webfactory.de"
	$sig535 = "someone@contoso.com"
	$sig536 = "ss@ssss.org"
	$sig537 = "ssc@sscs.com"
	$sig538 = "sss@scamredirector.cash"
	$sig539 = "stan@sc8s.com"
	$sig540 = "stof@notk.org"
	$sig541 = "supertool@mxtoolbox.com"
	$sig542 = "support@dchat.org"
	$sig543 = "support@it.com"
	$sig544 = "support@spammer.com"
	$sig545 = "sven@karlsruhe.org"
	$sig546 = "tangerine@vlad.com"
	$sig547 = "team@tuxion.nl"
	$sig548 = "terje@braten.be"
	$sig549 = "thiagoama@mohmal.com"
	$sig550 = "thomas@tourlourat.com"
	$sig551 = "to@internal.com"
	$sig552 = "tomas@tatarko.sk"
	$sig553 = "user@amaviktor.co.uk"
	$sig554 = "victor@suumit.com"
	$sig555 = "virusx.el@live.fr"
	$sig556 = "ward@coding-tech.com"
	$sig557 = "webmaster@atlant.ru"
	$sig558 = "webmaster@chronoengine.com"
	$sig559 = "wirez@googledocs.org"
	$sig560 = "wow@goodresult.com"
	$sig561 = "xconsole@alboraaq.com"
	$sig562 = "xxxx@xxxx.com.br"
	$sig563 = "you@yourdomain.com"
	$sig564 = "yourname@yourdomain.com"
	$sig565 = "yrudyy@prs.net.ua"
	$sig566 = "zsilbi@zsilbi.hu"
	$sig567 = "mask.us2016@yandex.com"
	$sig568 = "mask.suntrust@gmail.com"
	$sig569 = "info@mail.com"
	$sig570 = "ikpu.ego@gmail.com"
	$sig571 = "gavinbrent2012@yahoo.com"
	$sig572 = "happy_milkman@exploit.im"
	$sig573 = "hitman@darkcity.com"
	$sig574 = "logzz@eduz.edu"
	$sig575 = "tiagoama82@gmail.co"
	$sig576 = "user@server.org"

    condition:
    
	any of them
}

