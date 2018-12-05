/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-16
   Identifier: data
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule magecart_5 {
   meta:
      description = "data - file magecart.txt"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2028-10-16"
      hash3 = "5dc6e5d9c6e1c25c2470fd343e7d061bf9b4a2c73fffd7c56eb205efd05dd6fa"
   strings:
	$s257 = "verifiedjs.com"
	$s258 = "verpayment.com"
	$s259 = "verpayments.com"
	$s260 = "vuserjs.com"
	$s261 = "web-info.me"
	$s262 = "web-rank.cc"
	$s263 = "web-stat.biz"
	$s264 = "web-stat.me"
	$s265 = "web-stats.cc"
	$s266 = "web-stats.pw"
	$s267 = "webfotce.me"
	$s268 = "webstatistic.pw"
	$s269 = "webstatistic.ws"
	$s270 = "whitelistjs.com"
	$s271 = "x-magesecurity.com"
	$s272 = "xmageform.com"
	$s273 = "xmageinfo.com"
	$s274 = "xmagejs.com"
	$s275 = "xmagesecurity.com"
	$s276 = "youpayme.info"
	$s277 = "zonejs.com"
	$s278 = "friend4cdn.com"
	$s279 = "g-statistic.com"
	$s280 = "bootstrap-js.com"
   condition:
       any of them
}

