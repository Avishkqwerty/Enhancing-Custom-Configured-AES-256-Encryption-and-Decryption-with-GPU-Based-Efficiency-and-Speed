# 23-331 GOLIATH - Secure Courier Digital Vault Drive

**Main objective**
<br>
Creating a secure device coded with secure software with the potential to securely migrate or physically transport large amounts of classified, confidential, and top-secret data to ensure the Confidentiality, Integrity and Availability of data from unauthorized access, corruption, or theft throughout its entire lifecycle when in transit physically.


**Main Research questions**
<br>
* Storing data securely is challenged because of the rapid development of technology and expose of secret data and data leakage prevention is so hard.<br> 

* Also when it comes to securely transporting or migrating large amounts of data using physically is not easy. Most of the devices are bulky and large as well as costs more.<br> 
 
* Most of these facilities are provided as services.<br> 
 
* How ever all these devices use the simple mechanism of encrypting and transporting data that is not up for the task as well as not accessible by everyone.<br> 
 
* For that reason a more miniaturized, lower power consuming device with advanced features is proposed in this research.<br>


**Individual research question**
<br>
*IT20199494*<br>
1. What is the effectiveness of enhancing password security through the implementation of salted hashing and key derivation functions in preventing brute-force attacks and unauthorized access to sensitive data?<br>


<br>*IT20215842*<br>
1. How to access control with privileges that has multi factor authentication, device syncing and identification methods as well as keeping constant logs on both user and device activity to reduce the threat and harden the human factor in the process?<br>
2. How to design and build a user friendly  product with the form factor and with a physically hardened structure and comprising of a speed performance and  memory capabilities and a backup power source that is capable of running a complex power consuming application features like RAID, Data wiping, Encryption/Decryption, log keeping etc?<br>

<br>*IT20200374*<br>
1. How to analyze the performance differences between CPU and GPU for encryption-decryption processes and identify the most efficient hardware allocation strategy?<br>
2. How to co-relate the algorithm with tier-based encryption-decryption while efficiently using end-user computational power?<br>


<br>*IT20206482*
1. How to improve data security and stop unauthorized access or data leakage during transport, a more compact, low-power device with enhanced features for safe data transfer which includes advanced data wiping capabilities?<br>



**Individual Objectives**
<br>
*IT20199494* - Enhancing Password Security through Salted Hashing and Key Derivation Functions for encryption and decryption using AES 256.<br>
<br>*IT20215842* - Creating the Home system and vault system to integrate device-user recognition, authorization, and authentication simultaneously and creating supervised boost, re-flash disabling mechanism, secure root access, light-weight log system and create the embedded system(Vault Drive).<br>
<br>*IT20200374* - Developing a fast, reliable and power efficient data wiping program that is optimized for the secure vault drive; Tamper detection and authenticated data wipe.<br>
<br>*IT20206482* - Developing an automated algorithm to optimize the hardware allocation strategy (parallel processing) between CPU and GPU for encryption-decryption processes, with the goal of improving efficiency.<br>

**Other necessary information**
<br>

**Git management instructions**
* We are doing master branch merges weekly. So by then all the features which could be merged in to the repo has to fully tested and marked as `In Review` in the JIRA board
* Each time you start commiting something, first pull the changes from upstream via `git pull` and resolve the conflicts.
* Each time before adding commits to a branch, make use of `git checkout <branch-name>` and then `git merge master`
* Once done, try `git add .` and `git commit -m "merge-conflicts-resolved-for-<branch-name>-<datetimestamp>"`

**Create PR/Merge Requests commits**
Once a feature is complete:
1. Create a PR/merge request
2. Tag it with the relavent JIRA issue ID (i.e.: GOL-001), and `prepend` it to PRs/Merge request's headline. 
For an example
`[GOL-001] Adding Python ORM support`
3. Add some meaningful content which would help a reviewer to troubleshoot
4. Add an assignee and reviewer
5. Once reviewed by another in the team (peer reviewed), merge the content.

Note: For documentation cases, you may consider adding `[DOC]` tag for each PR/MR