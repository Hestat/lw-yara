/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s4 = "magento.name"
	$s5 = "oh-polly.com"
	$s6 = "advocatecdn.com"
	$s7 = "bridge.industries"
	$s8 = "drberg.online"
	$s9 = "drberg.store"
	$s10 = "gtagaffilate.com"
	$s11 = "mycloudtrusted.com"
	$s12 = "nykoa.in"
	$s13 = "beforescripts.com"
	$s14 = "citwinery.com"
	$s15 = "dmaxjs.com"
	$s16 = "encoderform.com"
	$s17 = "encrypterforms.com"
	$s18 = "fastlscripts.com"
	$s19 = "mdelivry.com"
	$s20 = "newrellc.com"
	$s21 = "oklahomjs.com"
	$s22 = "orealjs.com"
	$s23 = "safeprivatcy.com"
	$s24 = "sucuri-js.com"
	$s25 = "validatorcc.com"
	$s26 = "vmaxjs.com"
	$s27 = "gamacdn.com"
	$s28 = "abuse-js.link"
	$s29 = "activaguard.com"
	$s30 = "afterscripts.com"
	$s31 = "alabamascripts.com"
	$s32 = "alfcdn.com"
	$s33 = "amasty.biz"
	$s34 = "analiticoscdn.com"
	$s35 = "angular.club"
	$s36 = "apismanagers.com"
	$s37 = "apissystem.com"
	$s38 = "assetmage.com"
	$s39 = "assetsbrain.com"
	$s40 = "assetsbraln.com"
	$s41 = "aw-test.com"
	$s42 = "awscan.eu"
	$s43 = "awscan.info"
	$s44 = "awtest.eu"
	$s45 = "baways.com"
	$s46 = "bbypass.pw"
	$s47 = "bm24.biz"
	$s48 = "bm24.info"
	$s49 = "bm24.org"
	$s50 = "bootstrapjs.com"
	$s51 = "brainpayments.com"
	$s52 = "braintcdn.com"
	$s53 = "brainterepayments.com"
	$s54 = "braintform.com"
	$s55 = "braintreepaumenls.com"
	$s56 = "braintreepauments.com"
	$s57 = "braintreepaymenls.com"
	$s58 = "bralntree.com"
	$s59 = "brazersd.top"
	$s60 = "brontocdn.com"
	$s61 = "busnguard.com"
	$s62 = "ccvalidate.com"
	$s63 = "cdn-js.link"
	$s64 = "cdnassels.com"
   condition:
       any of them
}

