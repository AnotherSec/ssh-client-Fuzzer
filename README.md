This module implements an SSH client protocol fuzzer that can test various SSH clients by sending fuzzed packets. It includes options for configuring fuzzing parameters and handles different states of the SSH protocol during the fuzzing process.

# 1. Save ssh_client_fuzzer.rb modules
cp ssh_client_fuzzer.rb /usr/share/metasploit-framework/modules/auxiliary/

# 2. Refresh modules
msfupdate

# 3. Run fuzzer
msfconsole  
use auxiliary/ssh_client_fuzzer  
set SRVPORT 2222  
set FUZZCMDS SSH_MSG_KEXINIT,SSH_MSG_NEWKEYS,SSH_MSG_SERVICE_REQUEST   
set STARTSIZE 1000    
set ENDSIZE 500000   
set CYCLIC true    
run        
