/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-06-08
   Identifier: case125
   Reference: https://github.com/Hestat/lw-yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule apache2_1_XMR_MINER {
   meta:
      description = "case125 - file apache2-1"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "b04dcace214ddb4f88efeb1a495bc123739abe8eb9815991f421e6466f893656"
   strings:
      $x1 = "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-stak-cpu/1.3.0-1.5.0\"},\"id\":1}" fullword ascii
      $s2 = "_ZNSt6vectorIN8executor13sck_error_logESaIS1_EE19_M_emplace_back_auxIJSsEEEvDpOT_" fullword ascii
      $s3 = "Autoconf failed: Printing config for a single thread. Please try to add new ones until the hashrate slows down." fullword ascii
      $s4 = "_ZNKSt7__cxx118time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE3getES4_S4_RSt8ios_baseRSt12_Ios_IostateP2tmPKwSD_" fullword ascii
      $s5 = "_ZNKSt7__cxx118time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE3getES4_S4_RSt8ios_baseRSt12_Ios_IostateP2tmPKcSD_" fullword ascii
      $s6 = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii
      $s7 = "_ZNKSt8time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE3getES3_S3_RSt8ios_baseRSt12_Ios_IostateP2tmPKwSC_" fullword ascii
      $s8 = "_ZNKSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE3getES3_S3_RSt8ios_baseRSt12_Ios_IostateP2tmPKcSC_" fullword ascii
      $s9 = "_ZTINSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEEE" fullword ascii
      $s10 = "_ZTSNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEEE" fullword ascii
      $s11 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEED0Ev" fullword ascii
      $s12 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEED1Ev" fullword ascii
      $s13 = "_ZTVNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEEE" fullword ascii
      $s14 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEED2Ev" fullword ascii
      $s15 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEE6_M_runEv" fullword ascii
      $s16 = "CONNECT error: Pool port number not specified, please use format <hostname>:<port>." fullword ascii
      $s17 = "The values are not optimal, please try to tweak the values based on notes in config.txt." fullword ascii
      $s18 = "_ZN8executor16log_result_errorEOSs" fullword ascii
      $s19 = "_ZNKSt9money_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE6do_getES3_S3_bRSt8ios_baseRSt12_Ios_IostateRSbIwS2_SaIwEE" fullword ascii
      $s20 = "_ZNKSt7__cxx118time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE11get_weekdayES4_S4_RSt8ios_baseRSt12_Ios_IostateP2tm" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 5000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_06_07_18_case125_apache2_XMR_MINER {
   meta:
      description = "case125 - file apache2"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "3d18f4f503a72a4246b1a13327745fab15f9b34f45e17d4f6e94a311427ad4da"
   strings:
      $x1 = "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-stak-cpu/1.3.0-1.5.0\"},\"id\":1}" fullword ascii
      $s2 = "_ZNKSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE14_M_get_deleterERKSt9type_info" fullword ascii
      $s3 = "_ZNKSt19__shared_ptr_accessISt5mutexLN9__gnu_cxx12_Lock_policyE2ELb0ELb0EE6_M_getEv" fullword ascii
      $s4 = "_ZNKSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE3getEv" fullword ascii
      $s5 = "_ZN8executor16log_result_errorEONSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
      $s6 = "_ZN8executor16log_socket_errorEONSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
      $s7 = "_ZNSt10__weak_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE9_M_assignEPS0_RKSt14__shared_countILS2_2EE" fullword ascii
      $s8 = "_ZNSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EEC4ERKSt10__weak_ptrIS0_LS2_2EESt9nothrow_t" fullword ascii
      $s9 = "Autoconf failed: Printing config for a single thread. Please try to add new ones until the hashrate slows down." fullword ascii
      $s10 = "_ZN8executor15hashrate_reportERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
      $s11 = "get<0, std::__future_base::_State_baseV2::_Make_ready*, std::default_delete<std::__future_base::_State_baseV2::_Make_ready> >" fullword ascii
      $s12 = "get<1, std::__future_base::_State_baseV2::_Make_ready*, std::default_delete<std::__future_base::_State_baseV2::_Make_ready> >" fullword ascii
      $s13 = "_ZNKSt19__shared_ptr_accessISt5mutexLN9__gnu_cxx12_Lock_policyE2ELb0ELb0EEdeEv" fullword ascii
      $s14 = "_ZNKSt19__shared_ptr_accessISt5mutexLN9__gnu_cxx12_Lock_policyE2ELb0ELb0EEptEv" fullword ascii
      $s15 = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii
      $s16 = "__shared_ptr_access<std::mutex, (__gnu_cxx::_Lock_policy)2, false, false>" fullword ascii
      $s17 = "not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugsbasic_string::_S_create" fullword ascii
      $s18 = "_ZNSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EEaSEOS3_" fullword ascii
      $s19 = "_ZNKSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EEcvbEv" fullword ascii
      $s20 = "_ZNSt12__shared_ptrISt5mutexLN9__gnu_cxx12_Lock_policyE2EE5resetEv" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 5000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule _apache2_apache2_1_0_XMR_MINER {
   meta:
      description = "case125 - from files apache2, apache2-1"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara"
      date = "2018-06-08"
      hash1 = "3d18f4f503a72a4246b1a13327745fab15f9b34f45e17d4f6e94a311427ad4da"
      hash2 = "b04dcace214ddb4f88efeb1a495bc123739abe8eb9815991f421e6466f893656"
   strings:
      $x1 = "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-stak-cpu/1.3.0-1.5.0\"},\"id\":1}" fullword ascii
      $s2 = "Autoconf failed: Printing config for a single thread. Please try to add new ones until the hashrate slows down." fullword ascii
      $s3 = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii
      $s4 = "CONNECT error: Pool port number not specified, please use format <hostname>:<port>." fullword ascii
      $s5 = "The values are not optimal, please try to tweak the values based on notes in config.txt." fullword ascii
      $s6 = "Pool connection lost. Waiting %lld s before retry (attempt %llu)." fullword ascii
      $s7 = "PARSE error: Login protocol error 1" fullword ascii
      $s8 = "PARSE error: Login protocol error 3" fullword ascii
      $s9 = "PARSE error: Login protocol error 2" fullword ascii
      $s10 = "_ZNSt18condition_variable4waitERSt11unique_lockISt5mutexE" fullword ascii
      $s11 = "_ZGTtNSt11logic_errorC2ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
      $s12 = "_ZGTtNSt11logic_errorC1ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
      $s13 = "_ZTISt11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii
      $s14 = "_ZTSSt11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii
      $s15 = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag" fullword ascii
      $s16 = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag" fullword ascii
      $s17 = "_Z26_txnal_logic_error_get_msgPv" fullword ascii
      $s18 = "execute_native_thread_routine_compat" fullword ascii
      $s19 = "_ZNSs12_S_constructIN9__gnu_cxx17__normal_iteratorIPcSsEEEES2_T_S4_RKSaIcESt20forward_iterator_tag" fullword ascii
      $s20 = "Autoconf failed: L3 size sanity check failed - %u KB." fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 5000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

