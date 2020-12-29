# How to Avoid Writing a Bad Crackme

Recently, I was promoted to a reviewer on crackmes.one (along with @zed). I am so honored with this and I appreciate the recognition and trust from @stan (creator of crackmes.one) and the entire community. The task for a reviewer is interesting, that I read submitted solutions and verify new crackmes. This allows me to grasp the latest trend on the website.

I did not tally the statistics, but there is a fairly good amount of new submissions (of both crackmes and solutions) every week. And most of them are nice! For me, crackmes.one is a place for reversers to exchange knowledge and joyfulness. So I am very glad that we see a steady flow of input. Now that we have three reviewers, and I hope an increase in the reviewing speed will shorten the feedback loop for contributors, which, in turn, will lead to more contributions from the community.

Nevertheless, some of the submissions did not meet our standards and got rejected. The reasons vary, but many of them are using existing obfuscator/protector. Among them, many have a dull verification algorithm and the sole challenge is to get past the obfuscator. We welcome the use of protectors/obfuscators, but we do not like the use of existing ones, especially commercial ones, e.g., VMP, WinLicense. These protectors are definitely breakable (trust me), but it is too hard for a crackme and it will take very long to solve. For folks who can do it, they would probably invest the time in some more important/interesting things, rather than spending a long time on it to break the protector, and only to find the actual algorithm is just on XOR.

Meanwhile, using existing tools deviates from the spirit of crackmes.one. As I wrote above, I believe this is a place for us reversers to `"exchange knowledge and joyfulness"`. We not only practice and improve our reversing skills but also share and obtain knowledge. However, using an existing tool does not help the author learn anything, beyond how to execute the tool, which is relatively simple. Conversely, if the author digs deep into an existing (open-source) tool, understands how it works, makes certain changes to defeat existing tools, s/he would learn more.

Below, I will list some of the things that we should better avoid when writing a crackme. Note, these rules are not absolute and I will write a longer version of explanation following it.

## Don'ts

1. Do not upload crackmes that are not written by you.
2. Do not upload malware or unwanted software of any kind, e.g., trojan, ransomware, adware, etc.
3. Do not use a commercial packer, protector, or obfuscator.
4. Do not upload a crackme that you cannot solve.
5. The crackme should not fail to execute. Please, no missing library dependencies or internal errors!
6. The crackme should not make network connections to any host other than localhost (127.0.0.1).
7. The crackme me should make it clear how it accepts/expects input (if any). And it should also clearly tell the player whether the input is correct.
8. The crackme must be solvable without guessing or a non-trivial amount of brute-forcing.
9. The crackme must be solvable in a reasonable time -- when solved optimally.
10. The crackme should not rely on any hardware unique identifier as part of the algorithm.
11. The crackme should not stack unrelated levels of protection together.


## Justifications

A reader might notice some of the items above are too restrictive. So I will now explain the reason to set them and some of the exceptions for it. Also, if you are in doubt about a specific crackme or crackme idea, please contact one of the reviewers on Discord.

1. The crackme should be the uploader's original work. Do not upload crackmes that have potential copyright issues. Do not upload crackmes you see on the Internet or in CTFs, unless you get permission to do so.
2. An exception is that one might make a pseudo-ransomware/malware that is a reverse engineering challenge. If that is the case, be sure to limit the damage to a very small and specific range (e.g., a `flag.txt` in the current dir), and state it clearly before the actual payload runs.
3. Using commercial packers, protectors, or obfuscators does not help challenge authors to learn and improve. And it could also take too long to solve. Also, avoid using any of these tools that already exist. Making your own or improving existing tools are very welcome!
4. Related to #3 and #8, do not make a crackme that even the author cannot solve.
5. This is a disappointing situation. Try to be compatible with more systems you target. Though we know that compatibility with all systems is impossible. At least test it on another computer and see if it works!
6. We discourage the use of network connections. Network traffic makes it harder to determine whether the program has any malicious behavior. If you need to have a network connection, only do that with the localhost. If you do not wish the player to temper with the "remote" server, still bundle the server and run it on the localhost, but tell the player not to reverse it. 
7. If the crackme accepts inputs, e.g., user name and passwords, do not obscure the way it reads it. Also, be honest and tell the player if s/he solves it. Do not accept fake flags. Do not hide the flag somewhere that cannot be triggered by code execution. Note, this rule does not state that a crackme has to do password validation. We do have crackmes that ask the player to defeat the anti-debugging or decrypt a file that gets encrypted. These are good and not affected by this rule. In other words, if you have a novel challenge style, explain it to the player so they do not get lost. 
8. Do not put the flag/secret in a function that is never gonna be executed. Do not make crackmes that the player has to guess something important to proceed.
9. Most crackmes can be solved instantly, or in a few seconds. I think a max 1-minute time limit is a reasonable recommended maximum.
11. Do not blindly add layers of protection, unless they form a cohesive unity. If protections are duplicated in large numbers, there should be a way to automatically tackle it. 