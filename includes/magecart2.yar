/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart_2 {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s66 = "cdnbronto.info"
	$s67 = "cdngoogle.com"
	$s68 = "cdnmage.com"
	$s69 = "cdnpayment.com"
	$s70 = "cdnppay.com"
	$s71 = "cdnrfv.com"
	$s72 = "cdnscriptx.com"
	$s73 = "cdnwhiltelist.com"
	$s74 = "cellubiue.com"
	$s75 = "cellublue.info"
	$s76 = "citywiners.com"
	$s77 = "cl0udfiare.com"
	$s78 = "cloud-jquery.com"
	$s79 = "cloud-jquery.net"
	$s80 = "cloud-jquery.org"
	$s81 = "cloud-privacy.com"
	$s82 = "cloudtrusted.org"
	$s83 = "cmytuok.top"
	$s84 = "codesmagento.com"
	$s85 = "configmage.com"
	$s86 = "configsysrc.com"
	$s87 = "configsysrc.info"
	$s88 = "connectbootstrap.com"
	$s89 = "controlmage.com"
	$s90 = "crtteo.com"
	$s91 = "d0ubletraffic.com"
	$s92 = "directvapar.com"
	$s93 = "directvaporonline.com"
	$s94 = "directvaporus.com"
	$s95 = "directvaprr.com"
	$s96 = "dobellonline.com"
	$s97 = "docstart.su"
	$s98 = "doublecllck.com"
	$s99 = "ebizmart.biz"
	$s100 = "encryptforms.com"
	$s101 = "fbcommerse.com"
	$s102 = "fbprotector.com"
	$s103 = "frashjs.com"
	$s104 = "ganalytlcs.com"
	$s105 = "gitformage.com"
	$s106 = "gitformlife.com"
	$s107 = "gitmage.com"
	$s108 = "googiecloud.com"
	$s109 = "googieservlce.com"
	$s110 = "googleprotectionshop.com"
	$s111 = "googlitagmanager.com"
	$s112 = "govfree.pw"
	$s113 = "icon-base.biz"
	$s114 = "informaer.com"
	$s115 = "informaer.net"
	$s116 = "informaer.ws"
	$s117 = "internalvaporgroup.com"
	$s118 = "invisiblename.com"
	$s119 = "invisiblename.pro"
	$s120 = "invisiblename.pw"
	$s121 = "javascloud.com"
	$s122 = "javascripts-system.com"
	$s123 = "jquery-cdn.top"
	$s124 = "jquery-cloud.net"
	$s125 = "jquery-cloud.org"
	$s126 = "jquery-code.su"
	$s127 = "jquery-libs.su"
	$s128 = "jquery-min.su"
   condition:
       any of them
}
