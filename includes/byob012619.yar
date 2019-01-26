/*
   Yara Rule Set
   Author: Brian Laskowski
   Date: 2019-01-26
   Identifier: byob
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule infected_01_26_19_byob_server {
   meta:
      description = "byob - file server.py"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-01-26"
      hash1 = "ae491b5c7ae7e5a3da29da6b261a686372f5044f9d93c0d722b0fc7fb21ab26f"
   strings:
      $x2 = "globals()['module_handler'] = subprocess.Popen('{} -m SimpleHTTPServer {}'.format(sys.executable, options.port + 1), 0, None" fullword ascii
      $s10 = "_ = os.popen(\"taskkill /pid {} /f\".format(os.getpid()) if os.name == 'nt' else \"kill -9 {}\".format(os.getpid())).read()" fullword ascii
      $s11 = "util.log(\"Invalid input type (expected '{}', received '{}')\".format(socket.socket, type(connection)))" fullword ascii
      $s13 = "Execute code directly in the context of the currently running process" fullword ascii
      $s15 = "task = globals()['c2'].database.handle_task({'task': command, 'session': self.info.get('uid')})" fullword ascii
      $s16 = "util.display(\"Hint: show usage information with the 'help' command\\n\", color='white', style='normal')" fullword ascii
      $s17 = "util.log(\"{} error: invalid data type '{}'\".format(self.display.func_name, type(info)))" fullword ascii
      $s18 = "util.log(\"unable to locate 'site-packages' in sys.path (directory containing user-installed packages/modules)\")" fullword ascii
      $s19 = "result = globals()['c2'].commands[cmd]['method'](action) if len(action) else globals()['c2'].commands[cmd]['method']()" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and
         filesize < 100KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}
