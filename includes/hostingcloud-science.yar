/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-09
   Identifier: 12-09-18
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://urlscan.io/result/f6ef277d-6340-4ec9-a913-57685ed46f7c/content/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_12_09_18_zduF {
   meta:
      description = "12-09-18 - file zduF.js"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-09"
      hash1 = "52da40de1fd2a0edfc16e393cadf43fe8add12a7aa21e5911b6b8fb21861a44a"
   strings:
      $x1 = "var a=['wrfDgMOxNMOL','bV5/KcKq','OCzCqMK8HA==','wrbDlMKoP3M=','wrDDjcKnesO9','w7DDtcKeJcOf','bloWw7El','wrNWGTJRwqI=','w5LDqsO1" ascii
      $x2 = "':nk['rTQDE'](nk[b('0x138','$A)c')](nk[b('0x139','G$ix')](qM[b('0x13a','2h5Z')](0x0,-0x1),'\\x5c'),qM[b('0x13b','0N7H')](nk['EyZ" ascii
      $s3 = "-\\x5cxa0])+','PDYpG':function(cL,cM){return cL+cM;},'pDdkI':function(cN,cO){return cN+cO;},'RfZME':function(cP,cQ){return cP+cQ" ascii
      $s4 = "script':function(VX){return mc[b('0x9a8','0N7H')](VX),VX;}}}),mc['ajaxPrefilter'](b('0x9a9','I)PN'),function(VY){Z[b('0x9aa','#" fullword ascii
      $s5 = "0x0,Eq)){if(void 0x0!==(lL=DX[b('0x472','%RgQ')](lO,Ej)))return lL;if(Z[b('0x473','alwn')](void 0x0,lL=Z['QpgBA'](E2,lO,Ej)))re" fullword ascii
      $s6 = "nQ===nR;},'YNGvi':function(nS,nT){return Z['LDWZJ'](nS,nT);},'LndXj':function(nU,nV){return Z[b('0xe9','Md2o')](nU,nV);},'Mqvls" fullword ascii
      $s7 = "iI!==iJ;},'LvqDZ':function(iK,iL){return iK!==iL;},'zZWhy':b('0x63','bXFk'),'QExUO':function(iM,iN){return iM in iN;},'HYHkI':f" fullword ascii
      $s8 = "hG(hH);},'BORuX':b('0x5e','9Wj1'),'mgZhk':function(hI,hJ){return hI in hJ;},'pmDad':function(hK,hL,hM){return hK(hL,hM);},'tiAC" fullword ascii
      $s9 = "0x0!==Y['set'](this,lN,Z['LHaXq'])||(this[b('0x82d','vOsz')]=lN));});if(lN)return(Y=mc[b('0x82e','idEd')][lN[b('0x7b9','ZD&B')]" fullword ascii
      $s10 = "eK!==eL;},'cjZjQ':b('0x41','C76^'),'BagAr':function(eM,eN){return eM+eN;},'snKRe':'notify','XTalV':b('0x42','gTz2'),'AbVjH':b('" fullword ascii
      $s11 = "Y,lL=M8[b('0x6ba','XCxy')][this[b('0x6bb','Gtb)')]];return this[b('0x6bc','alwn')][b('0x6bd','#[LR')]?this['pos']=Y=mc[b('0x6be" fullword ascii
      $s12 = "lN||(Y=lL['body']['appendChild'](lL['createElement'](lM)),lN=mc['css'](Y,Z[b('0x4ba','lAp]')]),Y[b('0x4bb','lAp]')]['removeChil" fullword ascii
      $s13 = "Y=PH[b('0x7ed','I)PN')];Y&&(Y[b('0x7ee','alwn')],Y[b('0x7ef','6Igu')]&&Y['parentNode'][b('0x7f0',')P51')]);}}),mc['each']([Z[b(" fullword ascii
      $s14 = "KJ(KK,KL,KM){var lM=EZ[b('0x650','Md2o')](KL);return lM?Math['max'](0x0,lM[0x2]-Z['BxOeg'](KM,0x0))+(lM[0x3]||'px'):KL;}functio" fullword ascii
      $s15 = "vh=vh[b('0x294','gTz2')](qw,qx),function(vn){return vi['ACprV']((vn[b('0x295','&#9B')]||vn[b('0x296','vOsz')]||vi[b('0x297','$A" fullword ascii
      $s16 = "bb(bc);},'HHSrt':function(bd,be,bf,bg,bh){return bd(be,bf,bg,bh);},'UpGAg':function(bi,bj){return bi(bj);},'VFrMV':function(bk," fullword ascii
      $s17 = "w6olZG1bwrUNwpkZwp3Ci8KuwqN1VMKuwpHDjsOxwq/DiDV7wqJgf8O6w7fCjkRsw5DCikw/wp95w4ZiTMKaw5tpD2HDllzCgMKOw63DvwbDtAQVTsK8w7kUZ8O4wqrC" ascii
      $s18 = "3ff&lM|0xdc00);},qy=/([\\0-\\x1f\\x7f]|^-?\\d)|^-$|[^\\0-\\x1f\\x7f-\\uFFFF\\w-]/g,qz=function(qM,qN){return qN?'" fullword ascii
      $s19 = "('0x8d0','GT]j'),'isLocal':Sz['test'](RD[b('0x8d1','jQ3y')]),'global':!0x0,'processData':!0x0,'async':!0x0,'contentType':'applic" ascii
      $s20 = "w5wJw5XCocOCFMO2Oglpwp/CgsKRbcOmw4cpwqfCk8K5wrUNw7fCgsKBw53CtmINw41deRplAi3CrMO5w77DvBHDghFqCx/DrRg8WMKrw7U3wo40wqBdw5vDoi8RGcOD" ascii
   condition:
      ( uint16(0) == 0x6176 and
         filesize < 2000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

