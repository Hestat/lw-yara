/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-07-29
   Identifier: sans-xme-072818
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule jquery_prettyphoto {
   meta:
      description = "sans-xme-072818 - file jquery.prettyphoto.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-07-29"
      hash1 = "977a811695dbbd370e162807e4c0fbc25c9fda8bba3417279c2f8ee1289a47e6"
   strings:
      $x1 = "$.prettyPhoto.close=function(){if($pp_overlay.is(\":animated\"))return;$.prettyPhoto.stopSlideshow();$pp_pic_holder.stop().find(" ascii
      $x2 = "movie='http://www.youtube.com/embed/'+movie_id;(getParam('rel',pp_images[set_position]))?movie+=\"?rel=\"+getParam('rel',pp_imag" ascii
      $x3 = "if(settings.autoplay_slideshow&&!pp_slideshow&&!pp_open)$.prettyPhoto.startSlideshow();settings.changepicturecallback();pp_open=" ascii
      $s4 = "</div>',image_markup:'<img id=\"fullResImage\" src=\"{path}\" />',flash_markup:'<object classid=\"clsid:D27CDB6E-AE6D-11cf-96B8-" ascii
      $s5 = "if($.browser.msie&&$.browser.version==6)$('select').css('visibility','hidden');if(settings.hideflash)$('object,embed,iframe[src*" ascii
      $s6 = "$.prettyPhoto.open=function(event){if(typeof settings==\"undefined\"){settings=pp_settings;if($.browser.msie&&$.browser.version=" ascii
      $s7 = "return;$pp_pic_holder.css({'top':projectedTop,'left':(windowWidth/2)+scroll_pos['scrollLeft']-(contentwidth/2)});};};function _g" ascii
      $s8 = "$pp_pic_holder.fadeIn(function(){(settings.show_title&&pp_titles[set_position]!=\"\"&&typeof pp_titles[set_position]!=\"undefine" ascii
      $s9 = "function _getFileType(itemSrc){if(itemSrc.match(/youtube\\.com\\/watch/i)||itemSrc.match(/youtu\\.be/i)){return'youtube';}else i" ascii
      $s10 = "$.prettyPhoto.close();e.preventDefault();break;};};};});};$.prettyPhoto.initialize=function(){settings=pp_settings;if(settings.t" ascii
      $s11 = "/quicktime\" pluginspage=\"http://www.apple.com/quicktime/download/\"></embed></object>',iframe_markup:'<iframe src =\"{path}\" " ascii
      $s12 = "=false;pp_dimensions=_fitToViewport(movie_width,movie_height);doresize=true;skipInjection=true;$.get(pp_images[set_position],fun" ascii
      $s13 = "ader.onload=function(){pp_dimensions=_fitToViewport(imgPreloader.width,imgPreloader.height);_showContent();};imgPreloader.onerro" ascii
      $s14 = "script type=\"text/javascript\" src=\"http://platform.twitter.com/widgets.js\"></script></div><div class=\"facebook\"><iframe sr" ascii
      $s15 = "new Function(atob(\"dmFyIF8weDQ5ZTY9WydjYW5jZWxlZCcsJ2Vycm9yJywnb3B0X2luX2NhbmNlbGVkJywnX2Nvbm5lY3QnLCdsYXN0UGluZ1JlY2VpdmVkJywn" ascii
      $s16 = "Author: Stephane Caron (http://www.no-margin-for-errors.com)" fullword ascii
      $s17 = "if($.browser.msie&&$.browser.version==6)$('select').css('visibility','hidden');if(settings.hideflash)$('object,embed,iframe[src*" ascii
      $s18 = "movie='http://www.youtube.com/embed/'+movie_id;(getParam('rel',pp_images[set_position]))?movie+=\"?rel=\"+getParam('rel',pp_imag" ascii
      $s19 = "function getParam(name,url){name=name.replace(/[\\[]/,\"\\\\\\[\").replace(/[\\]]/,\"\\\\\\]\");var regexS=\"[\\\\?&]\"+name+\"=" ascii
      $s20 = "n=(arguments[3])?arguments[3]:0;_build_overlay(event.target);}" fullword ascii
   condition:
      ( uint16(0) == 0x2a2f and
         filesize < 700KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

