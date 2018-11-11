/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_7

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig385 = "dk@sum.lt"
	$sig386 = "douglas@crockford.com"
	$sig387 = "drak@zikula.org"
	$sig388 = "duda@big.hu"
	$sig389 = "dxdiag@goodpostman.com"
	$sig390 = "e@npd.lv"
	$sig391 = "elias@torrez.us"
	$sig392 = "elnur@elnur.pro"
	$sig397 = "eric@themepark.com"
	$sig398 = "eric@uxdriven.com"
	$sig399 = "ermin@islamagic.com"
	$sig400 = "fabien.potencier@symfony-project.com"
	$sig401 = "fabien@symfony.com"
	$sig402 = "faked@attacker.org"
	$sig403 = "florian@eckerstorfer.org"
	$sig404 = "foo@bar.com"
	$sig405 = "fred@another-site.co.uk"
	$sig406 = "gabbay@gabbay.com.br"
	$sig407 = "gabest@fre	$sig408 = .hu"
	$sig409 = "gajdaw@gajdaw.pl"
	$sig410 = "gerard@interfold.com"
	$sig411 = "gerd@php-tools.net"
	$sig412 = "gfrazier@icestorm.net"
	$sig413 = "git@flevour.net"
	$sig414 = "glen@delfi.ee"
	$sig415 = "gp_support@geoplugin.com"
	$sig416 = "hal@csolve.net"
	$sig417 = "hard@dreambig.com"
	$sig418 = "hrayr@bits.am"
	$sig419 = "hsbc@help.com"
	$sig420 = "hsivonen@iki.fi"
	$sig421 = "hugo.hamon@sensio.com"
	$sig422 = "i18n@forstwoof.ru"
	$sig423 = "i@teddysun.com"
	$sig424 = "iam@chebba.org"
	$sig425 = "iamjiboss25@tutanota.com"
	$sig426 = "igor@wiedler.ch"
	$sig427 = "info@getid3.org"
	$sig428 = "info@malitarh.ir"
	$sig429 = "info@rumail.com"
	$sig430 = "info@setpro.pl"
	$sig431 = "info@stokkebro.dk"
	$sig432 = "info@tarahc.ir"
	$sig433 = "info@themepunch.com"
	$sig434 = "info@wsgolden.ir"
	$sig435 = "is@swiftmailer.org"
	$sig436 = "j.boggiano@seld.be"
	$sig437 = "jeanfrancois.simon@sensiolabs.com"
	$sig438 = "jery@hartes.com"
	$sig439 = "jim@jagunet.com"
	$sig440 = "johan@linner.biz"
	$sig441 = "john@doe.com"
	$sig442 = "john@johnkary.net"
	$sig443 = "john@some-site.com"
	$sig444 = "js@schumann-it.com"
	$sig445 = "json@teczno.com"
	$sig446 = "justin@visunet.ie"
	$sig447 = "kami@kamisama.me"
	$sig448 = "kellan@protest.net"

    condition:
    
	any of them
}

