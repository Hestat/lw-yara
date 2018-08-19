/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-18
   Identifier: 08-18-18
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_4dd6090f04 {
   meta:
      description = "08-18-18 - file 4dd6090f04.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-18"
      hash1 = "b3166068189c84f5ed00642fb82fb1ce77c8a51cfc3619fe4e75763cc088e73b"
   strings:
      $x1 = "PclZip::privErrorLog(PCLZIP_ERR_BAD_FORMAT, 'gzip temporary file \\''.$v_gzip_temp_name.'\\' has invalid filesize - should be " fullword ascii
      $x2 = "PclZip::privErrorLog(PCLZIP_ERR_READ_OPEN_FAIL, 'Unable to open temporary file \\''.$v_zip_temp_name.'\\' in binary write mode" fullword ascii
      $x3 = "PclZip::privErrorLog(PCLZIP_ERR_READ_OPEN_FAIL, 'Unable to open temporary file \\''.$v_gzip_temp_name.'\\' in binary read mode" fullword ascii
      $s4 = "PclZip::privErrorLog(PCLZIP_ERR_UNSUPPORTED_ENCRYPTION, 'File \\''.$p_entry['filename'].'\\' is encrypted. Encrypted fil" fullword ascii
      $s5 = "PclZip::privErrorLog(PCLZIP_ERR_WRITE_OPEN_FAIL, 'Unable to open temporary file \\''.$v_gzip_temp_name.'\\' in binary write mo" fullword ascii
      $s6 = "PclZip::privErrorLog(PCLZIP_ERR_READ_OPEN_FAIL, 'Unable to open archive file \\''.$p_archive_filename.'\\' in binary write mod" fullword ascii
      $s7 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE, \"Invalid type \".gettype($v_value).\". Integer expected for att" fullword ascii
      $s8 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE, \"Invalid type \".gettype($v_value).\". String expected for attr" fullword ascii
      $s9 = "$p_header = unpack('vversion/vversion_extracted/vflag/vcompression/vmtime/vmdate/Vcrc/Vcompressed_size/Vsize/vfilename_len/vex" fullword ascii
      $s10 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_PARAMETER, \"Missing mandatory parameter \".PclZipUtilOptionText($key).\"(\".$key." fullword ascii
      $s11 = "if (($v_result = PclZipUtilCopyBlock($this->zip_fd, $v_temp_zip->zip_fd, $v_header_list[$i]['compressed_size'])) != 1)" fullword ascii
      $s12 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_OPTION_VALUE, \"Integer expected for option '\".PclZipUtilOptionText($p_options_" fullword ascii
      $s13 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_PARAMETER, \"Invalid optional parameter '\".$p_options_list[$i].\"' for this method\")" fullword ascii
      $s14 = "PclZip::privErrorLog(PCLZIP_ERR_MISSING_OPTION_VALUE, \"Missing parameter value for option '\".PclZipUtilOptionText($p_o" fullword ascii
      $s15 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_OPTION_VALUE, \"Wrong parameter value for option '\".PclZipUtilOptionText($p_opt" fullword ascii
      $s16 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE, \"Invalid empty short filename for attribute '\".PclZipUtilOpti" fullword ascii
      $s17 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE, \"Invalid empty filename for attribute '\".PclZipUtilOptionText" fullword ascii
      $s18 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_ATTRIBUTE_VALUE, \"Invalid empty full filename for attribute '\".PclZipUtilOptio" fullword ascii
      $s19 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_OPTION_VALUE, \"Function '\".$v_function_name.\"()' is not an existing function f" fullword ascii
      $s20 = "PclZip::privErrorLog(PCLZIP_ERR_INVALID_OPTION_VALUE, \"Value must be integer, string or array for option '\".PclZipUtil" fullword ascii
      $s21 = "base64_decode"
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 400KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
