/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-06
   Identifier: case122
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule _infected_case122_y_php_shell {
   meta:
      description = "case122 - file y.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-06"
      hash1 = "72ae0da8540453009cb64a6b151f2e452e76923d2bbb49e632c383c183aed3ad"
   strings:
      //$x1 = "<link rel=\"shortcut icon\" href=\"https://avatars2.githubusercontent.com/u/39534193?s=160&v=4\">" fullword ascii
      //$s2 = "unescape('%27%29%29%3b'));" fullword ascii
      $s3 = "20%3f%3a%2d%25%30%33%3c%33%36%30%3e%2a%2c%2a%76%68%63%67%29%3d%33%2d%26%32%35%2c%2a%30%2d%25%30%33%3b%33%37%3d%2a%2a%3d%2a%70%70" ascii /* hex encoded string ' ?:-%03<360>*,*vhcg)=3-&25,*0-%03;37=**=*pp' */
      //$s4 = "Don't Steal This Script Fucker" fullword ascii
      $s5 = "67%68%59%64%72%6d%2d%23%64%65%7a%27%2a%5d%79%68%31%70%6c%6f%70%6b%7e%54%70%75%20%43%2b%67%70%63%7e%76%6b%78%74%33%63%71%65%74%31" ascii /* hex encoded string 'ghYdrm-#dez'*]yh1plopk~Tpu C+gpc~vkxt3cqet1' */
      $s6 = "21%20%7c%25%74%70%7b%3d%21%63%62%69%65%22%37%31%35%2b%21%38%23%37%76%7d%2a%3d%2a%74%77%62%72%74%61%72%77%75%3b%25%76%7b%74%66%71" ascii /* hex encoded string '! |%tp{=!cbie"715+!8#7v}*=*twbrtarwu;%v{tfq' */
      $s7 = "6b%60%43%28%34%31%6b%7a%71%75%73%37%6c%71%7b%69%6d%6e%67%71%64%76%33%63%74%76%31%6f%75%74%44%6a%66%78%6c%6d%79%46%50%68%6d%76%6a" ascii /* hex encoded string 'k`C(41kzqus7lq{imngqdv3ctv1outDjfxlmyFPhmvj' */
      $s8 = "6a%70%79%77%32%73%6a%7b%6b%34%3b%31%75%78%3c%6e%72%6d%77%73%3b%79%62%6f%75%6e%3d%66%67%6c%68%74%36%6a%74%61%73%74%3b%65%6a%79%77" ascii /* hex encoded string 'jpyw2sj{k4;1ux<nrmws;yboun=fglht6jtast;ejyw' */
      $s9 = "6a%6e%37%67%78%6f%72%62%74%6e%7a%71%21%45%25%23%75%78%71%78%25%3b%3a%3b%76%21%6a%6a%77%6b%6d%76%21%6f%71%77%72%64%77%62%70%23%3d" ascii /* hex encoded string 'jn7gxorbtnzq!E%#uxqx%;:;v!jjwkmv!oqwrdwbp#=' */
      $s10 = "6e%78%68%73%26%63%74%71%67%32%21%4a%74%21%63%64%74%26%70%7e%76%70%6f%7b%6e%64%21%79%72%75%26%74%77%6c%75%20%6b%6a%7a%6a%2b%66%6a" ascii /* hex encoded string 'nxhs&ctqg2!Jt!cdt&p~vpo{nd!yru&twlu kjzj+fj' */
      $s11 = "77%77%79%25%70%74%6d%72%65%62%76%65%2b%67%7a%75%76%7a%20%7e%6b%79%71%20%6a%71%68%77%26%70%6a%72%6f%6b%21%71%68%6a%2b%34%3a%36%35" ascii /* hex encoded string 'wwy%ptmrebve+gzuvz ~kyq jqhw&pjrok!qhj+4:65' */
   condition:
      ( uint16(0) == 0x683c and
         filesize < 30KB and
           all of them )
}

