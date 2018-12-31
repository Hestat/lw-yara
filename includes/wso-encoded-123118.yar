/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-12-31
   Identifier: 12-31-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_12_31_18_Z605 {
   meta:
      description = "12-31-18 - file Z605.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-12-31"
      hash1 = "d7cfdc4f2964c9fd8c5a4e8949175d7ff8d7694165777b58e529a3c5da93f390"
   strings:
      $s1 = "<?php $_4d5CKq=\"0m5o049y3rvjw7a2c52nf0cp455oq4seaib3wuk52q0f9i0lulrhw5rrwb3m4g0kawgvqenafjmaqvw7ht3wn2p9m1hx\";$_voWgmO=array(1" ascii
      $s2 = "dr4//EDknH/FQ0+8Ju477U79yh3+RRJ6Njxlz65+EZ/Hc8Etp6u8nvoJP+ZV69aIc67+w+QX20+aPOOXb2BrrWy8dWBvIT4OvQfrFTdSm5Zdam2FTP3g6Y/8WkvCD1mN" ascii
      $s3 = "kfxXnm8GHeoZfJPmpX8A/7qWqfy7Yix/pkn5/qMcFfD2P/IUgzrx5XO3puRdFO09LM03og1m1Qz75KdlL1Lsi1E8o/iJ9aCP/EBWy2rf9cZDPaQI+2DZe91czm+evd/m" ascii
      $s4 = "v9Z3Fz6b+iG1l+6PxktQfTPkwt+kPi7f5+SN/LPwwl+azaX4IvxeX/AHevRyY/FlWLuTvbuWcLvxAkItZOYiJz7zDW3E7PpJLfGTzqX28sQ5Pgg+lR3xk9n16+L1+Fkv" ascii
      $s5 = "PRW8kOvPIFm5F8YvJ/VGr8pnz6cD/L1V/DOl3nA/0S1P8EfK8t+mS8dzqew3zDFzVX6U9ID8IvGetPq93aWq+8N8PMO8G+Am/ovib1lv9PX2/Jful/r5aG3Se+3PO95n" ascii
      $s6 = "B9EiQGf+5gfwCr0n+Qasfdziv+YDs1V6sST+JURoOR04BvMU+s5vP95sg1GozcYofIwfxZFGRfK0yq3wtdLpfTPGQ853Ow0zPHXcsYpnzPD3p33tSjucDm57f3nC/S+v" ascii
      $s7 = "Y0P5Wm3b/8b6jwmA8eC6kynfNLHX+k3TzSN/DXg+UvqmfyL/Yor4klhL1FTPSwv6M8UjkNw/9G+jH499vyd4ULX4y4/qlYYZTbb3D/VOK9+l8oF4KPMkTrcOa+0Mae56" ascii
      $s8 = "hwB9bpql+Q/pzQ/5eN16i9dOb+r/i+yV/i+KRCfiQFf4L+lNX/gD8u5ZPF/lIfn66XocfM84Gbf9U+GOe6FawKmSIeNlp5mEc7N9Fff8eAeuKfvsl5K2L71D3y50afNg" ascii
      $s9 = "yjzH7D2VFz6/sQ8L66In8k2f4S1jPfNCneMp9iZ3GH+7Yt9Z/+fz3jT+2cEfkn+D5qmlaGvBX5mRflH6XH+zHhOLNXJL/SPYpsmuKF32Kj33TT5W+Vv4V8m91Bn+O9BX" ascii
      $s10 = "g5+JeQWfKH08dnc6vfUP6ZEfPh/rLN9E+T+qT/y4qyDvwqSN8josc8sLxt7bbeKnuTSv7pnv9lK6XDnn9w6mKh3Fe7VHqvgnU84zdS+xouynypWNJ+0nnsypTircm9Pn" ascii
      $s11 = "kL6hncb8Z/PtpxXwwa8QDPG8qsYFPvSd5HWekf9R8ePdQH1b7C/wt60/lLyr9echnd+eJNJ9vZiSPEfTP4Eq/LOYLkn6cH8/TpIkvTvsZK1nj+cjQHfjCYS99nlfWkY+" ascii
      $s12 = "30,30,31,9,81);$payload=\"7L1bd6JatzX8lwBD2pPLZQQMKXBxmih3KLYiMlWSmNL467/RxwRFo6nUeqrW3u9u31U1S8NhzjHHsY8+BkEti6X9+ui45cxIDN++q7" ascii
      $s13 = "+TKxX71fXpwbfMfnPJC+OQP4JfJ1b4El4vWPk08nfroobPg/OLgP/LPhMZtZ/9uQ/sfwo/mbIN/ozKT5nPsIGH6RXZsLn04d9w3lEPaNH+hX9Qd8Szm/MTC8NLVUfC/a" ascii
      $s14 = "ZU9KvC5/r8XWu8K1KH6bjQoaknTl/D/067Hy26iFd79FbFW8Hvkw+39CHZX+a6A/ZPgT/ItkX4DW6n+m8Mf9t+HjoP1HnUdmjZX3vW6biNzRg38LO5w2dL843oX7c9I8" ascii
      $s15 = "6Z/tjzZ3SDY0S+5+NYG94f070odvUl7r6lORz18tVPQHztTH/uUJ+j/NjcXM+eV51zfYA9oL03Yf95fnWsKeYb431HaL/w0X/6Gtjz7r7e/u1/d2h3+Ue/TZTx32MnLJ" ascii
      $s16 = "b0+b9TvejtoGP7NafEK9fwOdCf+6hf8gf7c7bwPM9dPajMy8l+Di/Bfk60teFUVB8QM9TMR77jeKZHPqP5HdRMN+ejnj5JpbIN1/lf7laj0F/LOwh58s67ws+K+A7If8" ascii
      $s17 = "VPd8qKYPjWcmDg/X7mQcui7wa8arSAvajmIa8IHz2zSkojNmpKdZPkJ0aQbfHPvxG6B+Rwt7MVtSf5wmoVf9eQsvCXzutfJZHg8rqr+b5Ki2C01IE7pHOf7P+ivRfstI" ascii
      $s18 = "x0vVj8seFSCZmpOKTdv5G1fAjMh6xU+87ja/GR3m5Um/LpnKyZX7G5OO8IfQDkz09+DN0XoGnuO2c/xbPtj74R0m2I39gVRz5917JPyP5kfGF/CmdV/IfwF/hYB5MSfq" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 200KB and
         ( 8 of them )
      ) or ( all of them )
}

