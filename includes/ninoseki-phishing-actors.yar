/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-11-11
   Identifier: 11-11-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference2: https://otx.alienvault.com/pulse/5be4187fa5e3b23021cf7ca8
   Reference3: https://twitter.com/ninoseki
*/


rule ninoseki_phishing_actor_emails_1

{

    meta:
       author = "Brian Laskowski"
       info = " emails associated as the recipents of phishing campaigns "

    strings:
    
	$sig1 = "zzxxccah22@gmail.com"
	$sig3 = "zero.vb@hotmail.com"
	$sig4 = "zaa@hotmail.com"
	$sig7 = "xp.res.de@gmail.com"
	$sig8 = "xdecock@gmail.com"
	$sig9 = "xcojad@gmail.com"
	$sig10 = "xcode@yandex.com"
	$sig12 = "wlevy1710@gmail.com"
	$sig13 = "wisema187@gmail.com"
	$sig14 = "wiretins@gmail.com"
	$sig15 = "wirerozay1@gmail.com"
	$sig16 = "wirebox1011313@gmail.com"
	$sig17 = "west.j85325@gmail.com"
	$sig18 = "warycray@gmail.com"
	$sig19 = "walkaway3@yandex.com"
	$sig20 = "waldio.webdesig21n@gmail.com"
	$sig22 = "vic.stanciu@gmail.com"
	$sig23 = "uwe.tews@googlemail.com"
	$sig25 = "uuf6429@gmail.com"
	$sig30 = "umpirsky@gmail.com"
	$sig31 = "turnmed009@gmail.com"
	$sig32 = "tulane1987@gmail.com"
	$sig33 = "tools@hotmail.com"
	$sig35 = "tlfbrito@gmail.com"
	$sig36 = "tititi.ass@gmail.com"
	$sig37 = "tititi.ass1@gmail.com"
	$sig38 = "timothy.mower@gmail.com"
	$sig39 = "tiagoama82@gmail.com"
	$sig40 = "thomasphart11@gmail.com"
	$sig41 = "thomasantonini59@gmail.com"
	$sig46 = "telnat@bnc.ca"
	$sig47 = "techouse@gmail.com"
	$sig48 = "team_pbg@yahoo.com"
	$sig49 = "tdr3esult@mail.com"
	$sig50 = "td@gmail.com"
	$sig51 = "taylorotwell@gmail.com"
	$sig52 = "sus.results@gmail.com"
	$sig54 = "suppakilla@gmail.com"
	$sig56 = "subscribe@googlegroups.com"
	$sig57 = "stewartpacific@gmail.com"
	$sig58 = "stevecarl20154@gmail.com"
	$sig59 = "spayrollcompany@gmail.com"
	$sig61 = "soywiz@php.net"
	$sig62 = "source@test.com"
	$sig64 = "someone@example.onmicrosoft.com"
	$sig65 = "someone@example.com"
	$sig66 = "someone@contoso.onmicrosoft.com"

    condition:
    
	any of them
}

