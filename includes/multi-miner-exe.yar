/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2018-08-22
   Identifier: miner-exe
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_08_22_18_miner_miner_exe_p {
   meta:
      description = "miner-exe - file p"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "(-(e)) != 35 || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s3 = "s->d1->w_msg_hdr.msg_len + ((s->version == DTLS1_VERSION) ? DTLS1_CCS_HEADER_LENGTH : 3) == (unsigned int)s->init_num" fullword ascii
      $s4 = "Rewinding stream by : %d bytes on url %s (size = %lld, maxdownload = %lld, bytecount = %lld, nread = %d)" fullword ascii
      $s5 = "((mutex)->__data.__kind & 127) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s6 = "*(sizeof(size_t)) < __alignof__ (long double) ? __alignof__ (long double) : 2 *(sizeof(size_t))) - 1)) & ~((2 *(sizeof(size_t))" fullword ascii
      $s7 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s8 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s9 = "(mutex->__data.__kind & PTHREAD_MUTEX_ROBUST_NORMAL_NP) == 0" fullword ascii
      $s10 = "(mutex->__data.__kind & PTHREAD_MUTEX_PRIO_INHERIT_NP) != 0" fullword ascii
      $s11 = "compiler: gcc -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -g -O2 -" ascii
      $s12 = "* (4 * 1024 * 1024 * sizeof(long))) - 1)))->ar_ptr : &main_arena)" fullword ascii
      $s13 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s14 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s15 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s16 = "*** Error in `%s': %s: 0x%s ***" fullword ascii
      $s17 = "== 1) ? __builtin_strcmp (&zone_names[info->idx], __tzname[tp->tm_isdst]) : (- (__extension__ ({ const unsigned char *__s2 = (c" fullword ascii
      $s18 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s19 = "FTP: login denied" fullword ascii
      $s20 = "__pthread_mutex_cond_lock_adjust" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 9000KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_s {
   meta:
      description = "miner-exe - file s"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s3 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s4 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s5 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      $s6 = "hash > target (false positive)" fullword ascii
      $s7 = "User-Agent: cpuminer/2.3.3" fullword ascii
      $s8 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
      $s9 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
      $s10 = "rpc2_login_decode" fullword ascii
      $s11 = "getwork failed, retry after %d seconds" fullword ascii
      $s12 = "Failed to call rpc command after %i tries" fullword ascii
      $s13 = "Failed to get Stratum session id" fullword ascii
      $s14 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
      $s15 = "hash <= target" fullword ascii
      $s16 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
      $s17 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
      $s18 = "-S, --syslog          use system log for output messages" fullword ascii
      $s19 = "%s: unsupported non-option argument '%s'" fullword ascii
      $s20 = "Skein1024_Process_Block" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 700KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_m {
   meta:
      description = "miner-exe - file m"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s3 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s4 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s5 = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii
      $s6 = "pthread_mutex_destroy@@GLIBC_2.2.5" fullword ascii
      $s7 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      $s8 = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii
      $s9 = "pthread_mutex_init@@GLIBC_2.2.5" fullword ascii
      $s10 = "hash > target (false positive)" fullword ascii
      $s11 = "User-Agent: cpuminer/2.3.3" fullword ascii
      $s12 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
      $s13 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
      $s14 = "rpc2_login_decode" fullword ascii
      $s15 = "getwork failed, retry after %d seconds" fullword ascii
      $s16 = "Failed to call rpc command after %i tries" fullword ascii
      $s17 = "Failed to get Stratum session id" fullword ascii
      $s18 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
      $s19 = "hash <= target" fullword ascii
      $s20 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 500KB and
         ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_g {
   meta:
      description = "miner-exe - file g"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"
   strings:
      $s1 = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" fullword ascii
      $s2 = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" fullword ascii
      $s3 = "+ 1) - (size_t)(const void *)(__tzname[tp->tm_isdst]) == 1) && (__s2_len = __builtin_strlen (__tzname[tp->tm_isdst]), __s2_len " fullword ascii
      $s4 = "= (__s1[2] - ((__const unsigned char *) (__const char *) (__tzname[tp->tm_isdst]))[2]); if (__s2_len > 2 && __result == 0) __re" fullword ascii
      $s5 = "ize_t))) - 1)) & ~((2 * (sizeof(size_t))) - 1))) && ((old_top)->size & 0x1) && ((unsigned long)old_end & pagemask) == 0)" fullword ascii
      $s6 = "(((unsigned long)(((void*)((char*)(p) + 2*(sizeof(size_t))))) & ((2 * (sizeof(size_t))) - 1)) == 0)" fullword ascii
      $s7 = "((unsigned long)((void*)((char*)(brk) + 2*(sizeof(size_t)))) & ((2 * (sizeof(size_t))) - 1)) == 0" fullword ascii
      $s8 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s9 = "- ((__const unsigned char *) (__const char *) (__tzname[tp->tm_isdst]))[0]; if (__s2_len > 0 && __result == 0) { __result = (__" fullword ascii
      $s10 = "((size_t)((void*)((char*)(mm) + 2*(sizeof(size_t)))) & ((2 * (sizeof(size_t))) - 1)) == 0" fullword ascii
      $s11 = "Fake name process" fullword ascii
      $s12 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii
      $s13 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s14 = "relocation processing: %s%s" fullword ascii
      $s15 = "ELF load command address/offset not properly aligned" fullword ascii
      $s16 = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
      $s17 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s18 = "__pthread_mutex_lock" fullword ascii
      $s19 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
      $s20 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 2000KB and
         ( 8 of them )
      ) or ( all of them )
}

rule infected_08_22_18_miner_miner_exe_f {
   meta:
      description = "miner-exe - file f"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "45ed59d5b27d22567d91a65623d3b7f11726f55b497c383bc2d8d330e5e17161"
   strings:
      $s1 = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" fullword ascii
      $s2 = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" fullword ascii
      $s3 = "Fake name process" fullword ascii
      $s4 = "Couldn't execute" fullword ascii
      $s5 = "==> Fakename: %s PidNum: %d" fullword ascii
      $s6 = "execv@@GLIBC_2.0" fullword ascii
      $s7 = "Error: /dev/null" fullword ascii
      $s8 = "getpwnam" fullword ascii
      $s9 = "<command line>" fullword ascii
      $s10 = "getgrnam" fullword ascii
      $s11 = "Change UID/GID, use another user (optional)" fullword ascii
      $s12 = "/usr/src/packages/BUILD/glibc-2.3/cc/config.h" fullword ascii
      $s13 = "__i686.get_pc_thunk.bx" fullword ascii
      $s14 = ".gnu.version" fullword ascii
      $s15 = ".gnu.version_r" fullword ascii
      $s16 = "getenv@@GLIBC_2.0" fullword ascii
      $s17 = "getpid@@GLIBC_2.0" fullword ascii
      $s18 = "getcwd@@GLIBC_2.0" fullword ascii
      $s19 = "getgrnam@@GLIBC_2.0" fullword ascii
      $s20 = "getpwnam@@GLIBC_2.0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
         filesize < 40KB and
         ( 8 of them )
      ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule miner_g_p_0 {
   meta:
      description = "miner-exe - from files g, p"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"
      hash2 = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"
   strings:
      $s1 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s2 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s3 = "relocation processing: %s%s" fullword ascii
      $s4 = "ELF load command address/offset not properly aligned" fullword ascii
      $s5 = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
      $s6 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s7 = "__pthread_mutex_lock" fullword ascii
      $s8 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
      $s9 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii
      $s10 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-1021) - 53) / 4" fullword ascii
      $s11 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-125) - 24) / 4" fullword ascii
      $s12 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-16381) - 64) / 4" fullword ascii
      $s13 = "headmap.len == archive_stat.st_size" fullword ascii
      $s14 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 4932 - 1)" fullword ascii
      $s15 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 38 - 1)" fullword ascii
      $s16 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 308 - 1)" fullword ascii
      $s17 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-307) - 53)" fullword ascii
      $s18 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-4931) - 64)" fullword ascii
      $s19 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-37) - 24)" fullword ascii
      $s20 = "(char *) ((void*)((char*)(p) + 2*(sizeof(size_t)))) + 4 * (sizeof(size_t)) <= paligned_mem" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule miner_s_m_1 {
   meta:
      description = "miner-exe - from files s, m"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
      hash2 = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
   strings:
      $s1 = "hash > target (false positive)" fullword ascii
      $s2 = "rpc2_login_decode" fullword ascii
      $s3 = "hash <= target" fullword ascii
      $s4 = "Skein1024_Process_Block" fullword ascii
      $s5 = "Skein_512_Process_Block" fullword ascii
      $s6 = "Skein_256_Process_Block" fullword ascii
      $s7 = "[X]^WTQRC@EFOLIJkhmngdabspuv" fullword ascii /* reversed goodware string 'vupsbadgnmhkJILOFE@CRQTW^]X[' */
      $s8 = "|yz;8=>7412# %&/,)*" fullword ascii /* reversed goodware string '*),/&% #2147>=8;zy|' */
      $s9 = "dump_to_strbuffer" fullword ascii
      $s10 = "rpc2_login_lock" fullword ascii
      $s11 = "rpc2_login" fullword ascii
      $s12 = "num_processors" fullword ascii
      $s13 = "Target: %s" fullword ascii
      $s14 = "json_dump_file" fullword ascii
      $s15 = "dump_string" fullword ascii
      $s16 = "|ungXQJC4=&/" fullword ascii /* reversed goodware string '/&=4CJQXgnu|' */
      $s17 = "rpc2_target" fullword ascii
      $s18 = "AO]Sywek1?-#" fullword ascii /* reversed goodware string '#-?1kewyS]OA' */
      $s19 = "dump_to_file" fullword ascii
      $s20 = "diff_to_target" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule miner_s_m_p_2 {
   meta:
      description = "miner-exe - from files s, m, p"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-22"
      hash1 = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
      hash2 = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
      hash3 = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"
   strings:
      $x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
      $s2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s3 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s4 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s5 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      $s6 = "User-Agent: cpuminer/2.3.3" fullword ascii
      $s7 = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
      $s8 = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
      $s9 = "getwork failed, retry after %d seconds" fullword ascii
      $s10 = "Failed to call rpc command after %i tries" fullword ascii
      $s11 = "Failed to get Stratum session id" fullword ascii
      $s12 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
      $s13 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
      $s14 = "-S, --syslog          use system log for output messages" fullword ascii
      $s15 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
      $s16 = "%s: unsupported non-option argument '%s'" fullword ascii
      $s17 = "-p, --pass=PASSWORD   password for mining server" fullword ascii
      $s18 = "client.get_version" fullword ascii
      $s19 = "Tried to call rpc2 command before authentication" fullword ascii
      $s20 = "-s, --scantime=N      upper bound on time spent scanning current work when" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 9000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}


