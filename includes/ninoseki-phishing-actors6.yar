/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_6

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig321 = "akalongman@gmail.com"
	$sig322 = "ajevremovic@gmail.com"
	$sig323 = "aida_tarh@yahoo.com"
	$sig324 = "adrien.brault@gmail.com"
	$sig325 = "admin@test.com"
	$sig326 = "admin@site.com"
	$sig327 = "admin@me.com"
	$sig328 = "admin@mail.com"
	$sig329 = "admin@joomla.org"
	$sig330 = "admin@fb.com"
	$sig331 = "admin@example.com"
	$sig332 = "adlawson@gmail.com"
	$sig333 = "adeniyimo54@gmail.com"
	$sig334 = "achfhr33@gmail.com"
	$sig335 = "abc123egypt@hotmail.com"
	$sig336 = "3d@serverx.com"
	$sig337 = "456@swiftmailer.org"
	$sig338 = "52@mohmal.com"
	$sig339 = "a6a0538fc2934ba2bed32e08741b2cd3@marca.python.live.cheggnet.com"
	$sig340 = "aag@adamgoforth.com"
	$sig341 = "adam@pancutt.com"
	$sig342 = "adamaflynn@criticaldevelopment.net"
	$sig343 = "admin@edoboy.de"
	$sig344 = "admin@namodg.com"
	$sig345 = "admin@svtokens.pw"
	$sig346 = "alex@chumakov.ru"
	$sig347 = "andi@splitbrain.org"
	$sig348 = "andy@andymoore.info"
	$sig349 = "anon@anon.com"
	$sig350 = "anon@ftp.com"
	$sig351 = "apache@apache.com"
	$sig352 = "apple@darklight.id"
	$sig353 = "arezultat2014@outlook.fr"
	$sig354 = "argh@php-tools.net"
	$sig355 = "bank@zbi.com"
	$sig356 = "bar@baz.com"
	$sig357 = "ben@benramsey.com"
	$sig358 = "benjamin@zikarsky.de"
	$sig359 = "bobotche@hotmail.fr"
	$sig360 = "boletophp@boletophp.com.br"
	$sig361 = "boris@yurchenko.pp.ua"
	$sig362 = "brain79@inwind.it"
	$sig363 = "brian@nesbot.com"
	$sig364 = "bschussek@symfony.com"
	$sig365 = "cc@internal.org"
	$sig366 = "cdi@thewebmasters.net"
	$sig367 = "cemina@wsfactory.com.co"
	$sig368 = "cfredrickson@linbeck.com"
	$sig369 = "chris.corbyn@swiftmailer.org"
	$sig370 = "chris@cs278.org"
	$sig371 = "chris@jalakai.co.uk"
	$sig372 = "chris@swiftmailer.org"
	$sig373 = "chris@w3style.co.uk"
	$sig374 = "christopher.kvarme@flashjab.com"
	$sig375 = "clemens@build2be.nl"
	$sig376 = "colin@colinfrei.com"
	$sig377 = "contact@jfsimon.fr"
	$sig378 = "contact@vinades.vn"
	$sig379 = "corp@susquehanna.org"
	$sig380 = "dairiki@dairiki.org"
	$sig381 = "dan@rootcube.com"
	$sig382 = "danilo@kvota.net"
	$sig383 = "diego@agudo.eti.br"
	$sig384 = "dietrich@ganx4.com"

    condition:
    
	any of them
}

