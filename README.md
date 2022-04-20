# PowerShell-Events-Monitor

## report.ps1

This script allows administrators to monitor Windows events, generating an HTML report and sent through email.  
Schedule the script on task manager to run every day, and collect all events generated such as: 

- User Rights Changes: 4704, 4670 
- Group Settings: 4727, 4728, 4729 
- Account Creation: 4720, 4726, 4732, 4733 
- Event Log Clearing: 1102 
- PowerShell Transcripts 
- User Login/Authentication Events: 4624, 4625 
- Object Monitoring (files and folders): 4663,4656 

## Report Example:
![image](https://user-images.githubusercontent.com/104074960/164303694-aeab83d0-87f4-48fe-a91d-ec75d37d1d41.png)

## detect.ps1

Schedule on task manager to run every minute and check RDP connections