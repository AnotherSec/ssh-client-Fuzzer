This module implements an SSH client protocol fuzzer that can test various SSH clients by sending fuzzed packets. It includes options for configuring fuzzing parameters and handles different states of the SSH protocol during the fuzzing process.

# 1. Save ssh_client_fuzzer.rb modules

```
cp ssh_client_fuzzer.rb /usr/share/metasploit-framework/modules/auxiliary/
```

# 2. Refresh modules
```
msfupdate
```

# 3 run fuzzer

msfconsole   
msf6 > reload_all   
msf6 > use auxiliary/ssh_client_fuzzer  
msf6 auxiliary(ssh_client_fuzzer) > show options  
msf6 auxiliary(ssh_client_fuzzer) > set SRVPORT 2222  
msf6 auxiliary(ssh_client_fuzzer) > run   

# 4. Test targets (new terminal)
ssh -p 2222 -o StrictHostKeyChecking=test@127.0.0.1    
putty -P 2222 127.0.0.1
