/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-10-28
   Identifier: shells
   Reference: https://github.com/Hestat/lw-yara/
   Reference: https://github.com/bediger4000/php-malware-analysis/tree/master/104.223.89.142-2017-11-30a
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_104_223_89_142_2017_11_30a_shells_dc1 {
   meta:
      description = "shells - file dc1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "21bfa2844fc3856efa205ae3a85799bce7bed07e48546f1063c87ef4f247af16"
   strings:
      $s1 = "file_put_contents($Folder.\"wp-newsletter-v1.php\", base64_decode(\"PD9waHANCkBkYXRlX2RlZmF1bHRfdGltZXpvbmVfc2V0KCdFdXJvcGUvTG9u" ascii
      $s2 = "xLDR9KXs1fTp8KD8hKD86LipbYS1mMC05XTopezYsfSkoPz5bYS1mMC05XXsxLDR9KD8+OlthLWYwLTldezEsNH0pezAsNH0pPycgLiAnOjooPz4oPzpbYS1mMC05XXs" ascii /* base64 encoded string ',4}){5}:|(?!(?:.*[a-f0-9]:){6,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,4})?' . '::(?>(?:[a-f0-9]{' */
      $s3 = "7M30gT0sgaWQ9KC4qKS8nLCAnc2VuZG1haWwnID0+ICcvWzAtOV17M30gMi4wLjAgKC4qKSBNZXNzYWdlLycsICdwb3N0Zml4JyA9PiAnL1swLTldezN9IDIuMC4wIE9" ascii /* base64 encoded string '3} OK id=(.*)/', 'sendmail' => '/[0-9]{3} 2.0.0 (.*) Message/', 'postfix' => '/[0-9]{3} 2.0.0 O' */
      $s4 = "gJHRoaXMtPnNldEVycm9yKCJUaGUgcmVxdWVzdGVkIGF1dGhlbnRpY2F0aW9uIG1ldGhvZCBcIiRhdXRodHlwZVwiIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlIHNlcnZ" ascii /* base64 encoded string '$this->setError("The requested authentication method \"$authtype\" is not supported by the serv' */
      $s5 = "fc2VsZWN0b3IpICYmICghZW1wdHkoJHRoaXMtPkRLSU1fcHJpdmF0ZV9zdHJpbmcpIHx8ICghZW1wdHkoJHRoaXMtPkRLSU1fcHJpdmF0ZSkgJiYgZmlsZV9leGlzdHM" ascii /* base64 encoded string 'selector) && (!empty($this->DKIM_private_string) || (!empty($this->DKIM_private) && file_exists' */
      $s6 = "gb3IgJEZpbGVTY2FuID09ICIuLiIgb3IgaXNfZGlyKCRGaWxlU2Nhbikgb3IgIWlzX2ZpbGUoJEZpbGVTY2FuKSBvciAkRmlsZVNjYW4gPT0gYmFzZW5hbWUoX19GSUx" ascii /* base64 encoded string 'or $FileScan == ".." or is_dir($FileScan) or !is_file($FileScan) or $FileScan == basename(__FIL' */
      $s7 = "kZWJ1ZygiQ29ubmVjdGlvbjogb3BlbmluZyB0byAkaG9zdDokcG9ydCwgc29ja3M9eyR0aGlzLT5Tb2Nrc0hvc3R9OnskdGhpcy0+U29ja3NQb3J0fSwgdGltZW91dD0" ascii /* base64 encoded string 'ebug("Connection: opening to $host:$port, socks={$this->SocksHost}:{$this->SocksPort}, timeout=' */
      $s8 = "xOyBhPScgLiAkREtJTXNpZ25hdHVyZVR5cGUgLiAnOyBxPScgLiAkREtJTXF1ZXJ5IC4gJzsgbD0nIC4gJERLSU1sZW4gLiAnOyBzPScgLiAkdGhpcy0+REtJTV9zZWx" ascii /* base64 encoded string '; a=' . $DKIMsignatureType . '; q=' . $DKIMquery . '; l=' . $DKIMlen . '; s=' . $this->DKIM_sel' */
      $s9 = "3Rl18XFxcW1x4MDAtXHhGRl0pKSoiKScgLiAnKD8+XC4oPz5bISMtXCcqK1wvLTk9P14tfi1dK3wiKD8+KD8+W1x4MDEtXHgwOFx4MEJceDBDXHgwRS0hIy1cW1xdLVx" ascii /* base64 encoded string 'F]|\\\[\x00-\xFF]))*")' . '(?>\.(?>[!#-\'*+\/-9=?^-~-]+|"(?>(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\' */
      $s10 = "pcy0+bWFpbEhlYWRlciAuPSAkdGhpcy0+aGVhZGVyTGluZSgnU3ViamVjdCcsICR0aGlzLT5lbmNvZGVIZWFkZXIoJHRoaXMtPnNlY3VyZUhlYWRlcih0cmltKCR0aGl" ascii /* base64 encoded string 's->mailHeader .= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader(trim($thi' */
      $s11 = "haWwnXSAuICImc3ViamVjdD0iIC4gJF9HRVRbJ3N1YmplY3QnXSAuICImZnJvbT0iIC4gJF9HRVRbJ2Zyb20nXSAuICImcmVhbF91cmw9IiAuICRfR0VUWydyZWFsX3V" ascii /* base64 encoded string 'il'] . "&subject=" . $_GET['subject'] . "&from=" . $_GET['from'] . "&real_url=" . $_GET['real_u' */
      $s12 = "pKD8+OicgLiAnW2EtZjAtOV17MSw0fSl7N318KD8hKD86LipbYS1mMC05XVs6XF1dKXs4LH0pKD8+W2EtZjAtOV17MSw0fSg/PjpbYS1mMC05XXsxLDR9KXswLDZ9KT8" ascii /* base64 encoded string '(?>:' . '[a-f0-9]{1,4}){7}|(?!(?:.*[a-f0-9][:\]]){8,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?' */
      $s13 = "gIHNlbGY6OmVkZWJ1ZygnQXV0aCBtZXRob2QgcmVxdWVzdGVkOiAnIC4gKCRhdXRodHlwZSA/ICRhdXRodHlwZSA6ICdVTktOT1dOJyksIHNlbGY6OkRFQlVHX0xPV0x" ascii /* base64 encoded string ' self::edebug('Auth method requested: ' . ($authtype ? $authtype : 'UNKNOWN'), self::DEBUG_LOWL' */
      $s14 = "kcmVzdWx0IC49ICR0aGlzLT5oZWFkZXJMaW5lKCdTdWJqZWN0JywgJHRoaXMtPmVuY29kZUhlYWRlcigkdGhpcy0+c2VjdXJlSGVhZGVyKCR0aGlzLT5TdWJqZWN0KSk" ascii /* base64 encoded string 'result .= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader($this->Subject))' */
      $s15 = "gR2V0UGFnZUNvbnRlbnQodXJsZGVjb2RlKCRfR0VUWydyZWFsX3VybCddKSAuICI/Y2hlY2tfaW5ib3hfcGhwX2FjdGlvbj10cnVlJmVtYWlsPSIgLiAkX0dFVFsnZW1" ascii /* base64 encoded string 'GetPageContent(urldecode($_GET['real_url']) . "?check_inbox_php_action=true&email=" . $_GET['em' */
      $s16 = "wRFx4MEEpP1tcdCBdKyk/KShcKCg/Pig/MiknIC4gJyg/PltceDAxLVx4MDhceDBCXHgwQ1x4MEUtXCcqLVxbXF0tXHg3Rl18XFxcW1x4MDAtXHg3Rl18KD8zKSkpKig" ascii /* base64 encoded string 'D\x0A)?[\t ]+)?)(\((?>(?2)' . '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(' */
      $s17 = "/ISg/Pig/MSkiPyg/PlxcXFsgLX5dfFteIl0pIj8oPzEpKXs2NSx9QCknIC4gJygoPz4oPz4oPz4oKD8+KD8+KD8+XHgwRFx4MEEpP1tcdCBdKSt8KD8+W1x0IF0qXHg" ascii /* base64 encoded string '!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' . '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x' */
      $s18 = "oPz5cXFxbIC1+XXxbXiJdKSI/KXs2NSx9QCkoPz4nIC4gJ1shIy1cJyorXC8tOT0/Xi1+LV0rfCIoPz4oPz5bXHgwMS1ceDA4XHgwQlx4MENceDBFLSEjLVxbXF0tXHg" ascii /* base64 encoded string '?>\\\[ -~]|[^"])"?){65,}@)(?>' . '[!#-\'*+\/-9=?^-~-]+|"(?>(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x' */
      $s19 = "nIC4gJzo6KD8+W2EtZjAtOV17MSw0fSg/PjpbYS1mMC05XXsxLDR9KXswLDZ9KT8pKXwoPz4oPz5JUHY2Oig/PlthLWYwLTldezEsNH0oPz46JyAuICdbYS1mMC05XXs" ascii /* base64 encoded string ' . '::(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?))|(?>(?>IPv6:(?>[a-f0-9]{1,4}(?>:' . '[a-f0-9]{' */
      $s20 = "7MSw0fSkoPz46KD82KSl7N30nIC4gJ3woPyEoPzouKlthLWYwLTldWzpcXV0pezgsfSkoKD82KSg/PjooPzYpKXswLDZ9KT86Oig/Nyk/KSl8KD8+KD8+SVB2NjooPz4" ascii /* base64 encoded string '1,4})(?>:(?6)){7}' . '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>' */
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 600KB and
         ( 8 of them )
      ) or ( all of them )
}

rule wp_newsletter_v1 {
   meta:
      description = "shells - file wp-newsletter-v1.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-10-28"
      hash1 = "eec9fc9c2a24434541e7b3b26f5401a81ffbc12ecbbe3c0e728fecee71146259"
   strings:
      $x1 = "curl_setopt($ch, CURLOPT_USERAGENT, \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 6.1; .NET CLR 1.1.4322)\");" fullword ascii
      $x2 = "if ($urlShell === false && preg_match('/' . preg_quote(\"[shell_rewrite_url]\", \"/\") . '/i', $Command['content'])) {" fullword ascii
      $s3 = "$privKeyStr = !empty($this->DKIM_private_string) ? $this->DKIM_private_string : @file_get_contents($this->DKIM_private);" fullword ascii
      $s4 = "$mime[] = sprintf('Content-Type: %s; name=\"%s\"%s', $type, $this->encodeHeader($this->secureHeader($name)), $this->LE);" fullword ascii
      $s5 = "if (version_compare(PHP_VERSION, '5.3.0') >= 0 and in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {" fullword ascii
      $s6 = "if (!$this->sendCommand('User & Password', base64_encode(\"\\0\" . $username . \"\\0\" . $password), 235)) {" fullword ascii
      $s7 = "$checkread = @GetPageContent(' . $Function2 . '() . $image_name . \"?\" . http_build_query($parameters) );" fullword ascii
      $s8 = "$mime[] = sprintf('Content-Type: %s; name=\"%s\"%s', $type, $this->encodeHeader($this->secureHeader($name)), $" fullword ascii
      $s9 = "$mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $encoded_name, $this->LE . $this->LE);" fullword ascii
      $s10 = "$SERVER_INFOS['REAL_IP_GET']     = GetPageContent(\"http://myip.dnsomatic.com/\");" fullword ascii
      $s11 = "return $this->language[$key] . ' https://github.com/SilthxMailer/SilthxMailer/wiki/Troubleshooting';" fullword ascii
      $s12 = "$this->smtp_conn = @stream_socket_client($host . \":\" . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, " fullword ascii
      $s13 = "$mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $encoded_name, $this->LE ." fullword ascii
      $s14 = "$mail->addStringAttachment(GetPageContent($Command['file']), $Command['filename'] . \".\" . $FileExtension);" fullword ascii
      $s15 = "fwrite($SocksSocket, pack(\"C4Nn\", 0x05, 0x01, 0x00, 0x01, ip2long(gethostbyname($host)), $port));" fullword ascii
      $s16 = "return html_entity_decode(trim(strip_tags(preg_replace('/<(head|title|style|script)[^>]*>.*?<\\/\\\\1>/si', '', $html))), E" fullword ascii
      $s17 = "$noerror         = $this->sendCommand($hello, $hello . ' ' . $host, 250);" fullword ascii
      $s18 = "$this->edebug(\"The SOCKS server failed to connect to the specificed host and port. ( \" . $host . \":\" . $port . \"" fullword ascii
      $s19 = "return (strlen($address) >= 3 and strpos($address, '@') >= 1 and strpos($address, '@') != strlen($address) - 1);" fullword ascii
      $s20 = "$mime[] = sprintf('Content-Disposition: %s; filename=\"%s\"%s', $disposition, $encoded_name, $this->LE . $this->LE);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

