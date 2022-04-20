Param (
   [int]$Min =  1440, 
   $Sub = "Daily Report"
)
<#
Author: Régis Froemming
Date: February 06, 2022
Description: Windows Server Auditing  
#>


$header = @"
<style>
    h1 {
        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 28px;
    }

    
    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
    }

    body {
        font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
    }
    table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    #CreationDate {
        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;
    }
    #Transcription {
        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;
    }

    .StopStatus {
        color: #ff0000;
    }
  
    .RunningStatus {
        color: #008000;
    }
</style>
"@


$Min = $Min * -1
$ServerName = "<h1>Server name: $env:computername</h1>"
$StartTime =  [datetime]::Now.AddMinutes($Min)
$EndTime = [datetime]::Now
$StartTime
if ($Sub -ne "Daily Report")
{
    $Sub = "Report session user "+$Sub
}
$Sub
$path = "C:\Users\Administrator\AppData\LocalLow\Microsoft\Windows\System32"
#$path = "C:\Users\Administrator\Documents"
#####################
## RDP Events
#####################
Write-Output "RDP Logins"
$EventArray = @() 
$LogName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
$EventId = 21,22,23,24,25

#Get event data
$AllEvents = Get-WinEvent -FilterHashTable @{Logname = $LogName ; ID = $EventId; StartTime = $StartTime; EndTime = $EndTime } 
 
Foreach ($Event in $AllEvents) {

    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, SessionID, SourceIP
    #Convert event to XML
    $EventXML = [xml]$Event.ToXml()

    #Set event info variables
    $EventType= switch ($Event.Id)
    {
        21 {"Logon"}
        22 {"Shell start"}
        23 {"Logoff"}
        24 {"Disconnected"}
        25 {"Reconnection"}
        default {"Unknown"}
    }
        
    #Store event data in array
    #$Result.ComputerName = $ComputerName
    $Result.EventDescription = $EventType
    $Result.EventID = $Event.Id
    $Result.EventTime = $Event.TimeCreated
    $Result.Username = $EventXML.Event.UserData.EventXml.User
    $Result.SessionID = $EventXML.event.userdata.eventxml.SessionID
    $Result.SourceIP = $EventXML.event.userdata.eventxml.Address
    $EventArray += $Result
}
# Check if the array is empty
if (-not $EventArray)
{
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, SessionID, SourceIP

    #$Result.EventDescription = ""
    #$Result.EventID = ""
    $Result.EventTime = "No data"
    #$Result.Username = ""
    #$Result.SourceMachine = ""
    #$Result.FailureStatus = ""
    #$Result.FailureSubStatus = ""
    #$Result.SourceIP = ""
    $EventArray += $Result
}
$RDPLogins = $EventArray | ConvertTo-Html -Fragment -As Table  -PreContent "<h2>RDP Logins</h2>"

#####################
## Logins Events
#####################
$EventArray = @() 
Write-Output "Logins"
function Get-FailureReason {
    Param($FailureReason)
    switch ($FailureReason) {
        '0xC0000064' {"Account does not exist"; break;}
        '0xC000006A' {"Incorrect password"; break;}
        '0xC000006D' {"Incorrect username or password"; break;}
        '0xC000006E' {"Account restriction"; break;}
        '0xC000006F' {"Invalid logon hours"; break;}
        '0xC000015B' {"Logon type not granted"; break;}
        '0xc0000070' {"Invalid Workstation"; break;}
        '0xC0000071' {"Password expired"; break;}
        '0xC0000072' {"Account disabled"; break;}
        '0xC0000133' {"Time difference at DC"; break;}
        '0xC0000193' {"Account expired"; break;}
        '0xC0000224' {"Password must change"; break;}
        '0xC0000234' {"Account locked out"; break;}
        '0x0' {"0x0"; break;}
        default {"Other"; break;}
    }
}
$LogName = "Security"
$EventId = 4624

#Get data from event logs
$AllEvents = Get-WinEvent -FilterHashTable @{Logname = $LogName ; ID = $EventId; StartTime = $StartTime; EndTime = $EndTime; Data = '3' } -ErrorAction SilentlyContinue
   
Foreach ($Event in $AllEvents) {

    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, SourceMachine, LogonType, SourceIP

    #Convert event to XML
    $EventXML = [xml]$Event.ToXml()

    #Set event info variables
    $EventType= switch ($Event.Id)
    {
        4624 {"A successful account logon event"}
        4625 {"An account failed to log on"}
        4648 {"A logon was attempted using explicit credentials"}
        4634 {"An account was logged off"}
        4647 {"User initiated logoff"}
        default {"Unknown"}
    }
        
    #Store event data in array
    $Result.EventDescription = $EventType
    $Result.EventID = $Event.Id
    $Result.EventTime = $Event.TimeCreated
    $Result.Username = $EventXML.Event.EventData.Data[5].'#text'
    $Result.SourceMachine = $EventXML.Event.EventData.Data[11].'#text'
    $Result.LogonType = $EventXML.Event.EventData.Data[8].'#text'
    $Result.SourceIP = $EventXML.Event.EventData.Data[18].'#text'
    $EventArray += $Result
}
# Check if the array is empty
if (-not $EventArray)
{
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, SourceMachine, LogonType, SourceIP
    #$Result.EventDescription = ""
    #$Result.EventID = ""
    $Result.EventTime = "No data"
    #$Result.Username = ""
    #$Result.SourceMachine = ""
    #$Result.FailureStatus = ""
    #$Result.FailureSubStatus = ""
    #$Result.SourceIP = ""
    $EventArray += $Result
}
$SuccessLogins = $EventArray | ConvertTo-Html -Fragment -As Table  -PreContent "<h2>Successful Logins</h2>"

#####################
## Logins fails
#####################
$EventArray = @() 
Write-Output "Failed/Logins - BruteForce attack"
$EventId = 4625
$AllEvents = Get-WinEvent -FilterHashTable @{Logname = $LogName ; ID = $EventId; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction SilentlyContinue 
 
Foreach ($Event in $AllEvents) {

    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, SourceMachine, FailureStatus, FailureSubStatus, SourceIP
    
    #Convert event to XML
    $EventXML = [xml]$Event.ToXml()

    #Set event info variables
    $EventType= switch ($Event.Id)
    {
        4624 {"A successful account logon event"}
        4625 {"An account failed to log on"}
        4648 {"A logon was attempted using explicit credentials"}
        4634 {"An account was logged off"}
        4647 {"User initiated logoff"}
        default {"Unknown"}
    }
        
    #Store event data in array
    $Result.EventDescription = $EventType
    $Result.EventID = $Event.Id
    $Result.EventTime = $Event.TimeCreated
    $Result.Username = $EventXML.Event.EventData.Data[5].'#text'
    $Result.SourceMachine = $EventXML.Event.EventData.Data[13].'#text'
    $Result.FailureStatus = Get-FailureReason($EventXML.Event.EventData.Data[7].'#text')
    $Result.FailureSubStatus = Get-FailureReason($EventXML.Event.EventData.Data[9].'#text')
    $Result.SourceIP = $EventXML.Event.EventData.Data[19].'#text'
    $EventArray += $Result
}
# Check if the array is empty
if (-not $EventArray)
{
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, SourceMachine, FailureStatus, FailureSubStatus, SourceIP
    #$Result.EventDescription = ""
    #$Result.EventID = ""
    $Result.EventTime = "No data"
    #$Result.Username = ""
    #$Result.SourceMachine = ""
    #$Result.FailureStatus = ""
    #$Result.FailureSubStatus = ""
    #$Result.SourceIP = ""
    $EventArray += $Result
}
$FailLogins = $EventArray | ConvertTo-Html -Fragment -As Table  -PreContent "<h2>Failed Logons</h2>"


#####################################################
## Access to folders
#####################################################
## Don't forget to set auditing on folder !!!!!!!!!!!
#####################################################

$EventArray = @() 

Write-Output "Audit Object Access "
$EventId = 4663,4656
$AllEvents = Get-WinEvent -FilterHashTable @{Logname = $LogName ; ID = $EventId; StartTime = $StartTime; EndTime = $EndTime }
$Result_prev = "" | Select-Object EventTime, EventDescription, EventID, Username, ObjectName, ProcessName, AccessMask
# -ErrorAction SilentlyContinue 
Foreach ($Event in $AllEvents) {
    #Convert event to XML
    $EventXML = [xml]$Event.ToXml()
    
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, ObjectName, ProcessName, AccessMask
   
    #Store event data in array
    $AM = $EventXML.Event.EventData.Data[9].'#text'
    if ($Event.Id -eq 4656) {
        $AM = $EventXML.Event.EventData.Data[11].'#text'
    }
    else {
        $AM = $EventXML.Event.EventData.Data[9].'#text'
    }    
    
    if ($AM -eq '0x1' -or $AM -eq '0x2' -or $AM -eq '0x4' -or $AM -eq '0x20' -or $AM -eq '0x40' -or $AM -eq '0x100' -or $AM -eq '0x10000')
    {
        $AccessMask= switch ($AM)
        {
            '0x1' {'Read Data / List Directory'}
            '0x2' {'Write Data / Add File'}
            '0x4' {'Append Data / Create Subdirectory'}
            '0x20' {'Execute / Traverse Directory'}
            '0x40' {'Delete Directory and all children'}
            '0x100' {'Change file Attributes'}
            '0x10000' {'Delete'}
        }
        $Result.AccessMask = $AccessMask
        $Result.EventDescription = "An attempt was made to access an object"
        $Result.EventID = $Event.Id
        $Result.EventTime = $Event.TimeCreated
        $Result.Username = $EventXML.Event.EventData.Data[1].'#text'
        $Result.ObjectName = $EventXML.Event.EventData.Data[6].'#text'
        if ($Event.Id -eq 4656) {
            $Result.ProcessName = $EventXML.Event.EventData.Data[15].'#text'
        }
        else {
            $Result.ProcessName = $EventXML.Event.EventData.Data[11].'#text'
        } 
        # Check if events are the same, to avoid repetive data   
        if ($Result.AccessMask -eq $Result_prev.AccessMask -and $Result.EventDescription -eq $Result_prev.EventDescription -and $Result.EventTime.ToString("yyyyMMddHHmmss") -eq $Result_prev.EventTime.ToString("yyyyMMddHHmmss") -and ` 
            $Result.Username -eq $Result_prev.Username -and $Result.ObjectName -eq $Result_prev.ObjectName -and $Result.ProcessName -eq $Result_prev.ProcessName) 
        {
           
        }
        Else
        { 
            $EventArray += $Result
        }
        $Result_prev = $Result
    }
   

}
# Check if the array is empty
if (-not $EventArray)
{
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username, ObjectName, ProcessName, AccessMask

    #$Result.EventDescription = ""
    #$Result.EventID = ""
    $Result.EventTime = "No data"
    #$Result.Username = ""
    #$Result.SourceMachine = ""
    #$Result.FailureStatus = ""
    #$Result.FailureSubStatus = ""
    #$Result.SourceIP = ""
    $EventArray += $Result
}
$ObjectAccess = $EventArray | ConvertTo-Html -Fragment -As Table  -PreContent "<h2>Object Access</h2>"


####################################################################
## Clean Transcripts generated by the self executation of the script
####################################################################

# Copy files to a temporary folder to avoid error (windows keeps last transcript file open)
$source = "$path\$(Get-Date -Format "yyyyMMdd")\*.txt"
$dest = "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")" 
if ((Test-Path -path $dest) -eq $false) {
    New-Item -ItemType "directory" -Path $dest
}
Copy-Item -path $source -Destination $dest -Force


$allfiles = Get-ChildItem "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")" -Filter *.TXT  
Foreach ($file in $allfiles)
{
    $search = (Get-Content "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\$($file)"  | Select-String -Pattern 'detect.exe').Matches.Success
     if ($search)
        { 
            Remove-Item "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\$file" -Recurse -Force
        }
        else
        {
             $search = (Get-Content "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\$($file)"  | Select-String -Pattern 'Report.ps1').Matches.Success
             if ($search)
                { 
                    Remove-Item "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\$file" -Recurse -Force 
                }
                else
                {
                    $search = (Get-Content "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\$($file)"  | Select-String -Pattern 'detect.ps1').Matches.Success
                    if ($search)
                        { Remove-Item "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\$file" -Recurse -Force  }
                }
        }
}



######################
## Transcript files ##
######################
Write-Output "Transcriptions"
$Transcription = "<h2>PowerShell Transcriptions (Attachements)</h2>"
if  (Test-Path -Path "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")") {
    $List =  Get-ChildItem "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")"  | Sort CreationTime -Descending -ErrorAction SilentlyContinue
    ForEach ($File in $List) {
        $Transcription = $Transcription + "<li>$($File)</li>" 
    }
}
else
{
     $Transcription = $Transcription + "<table><a> No data</a></table>"
   
}



########################
## Detect log-cleared ##
########################
Write-Output "Detect log cleared"
$EventArray = @() 
$EventId = 1102
$AllEvents = Get-WinEvent -FilterHashTable @{Logname = $LogName ; ID = $EventId; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction SilentlyContinue
Foreach ($Event in $AllEvents) {
    #Convert event to XML
    $EventXML = [xml]$Event.ToXml()
    
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username
   
        
    #Store event data in array
    $Result.EventDescription = "The audit log was cleared"
    $Result.EventID = $Event.Id
    $Result.EventTime = $Event.TimeCreated
    $Result.Username = $EventXML.Event.UserData.LogFileCleared.SubjectUserName
    $EventArray += $Result
}
# Check if the array is empty
if (-not $EventArray)
{
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, Username

    #$Result.EventDescription = ""
    #$Result.EventID = ""
    $Result.EventTime = "No data"
    #$Result.Username = ""
    #$Result.SourceMachine = ""
    #$Result.FailureStatus = ""
    #$Result.FailureSubStatus = ""
    #$Result.SourceIP = ""
    $EventArray += $Result
}
$ClearLog = $EventArray | ConvertTo-Html -Fragment -As Table  -PreContent "<h2>Events Cleared</h2>"


#############################
## Account Creation/Change ##
#############################
Write-Output "Account management"
$EventArray = @() 
$EventId = 4720, 4726, 4732, 4733
$AllEvents = Get-WinEvent -FilterHashTable @{Logname = $LogName ; ID = $EventId; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction SilentlyContinue
Foreach ($Event in $AllEvents) {
    #Convert event to XML
    $EventXML = [xml]$Event.ToXml()
    
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, SamAccount, MemberOf,AddedRemovedGroup, SecurityID
    $Result.SamAccount = $EventXML.Event.EventData.Data[0].'#text'
    $Result.SecurityID = $EventXML.Event.EventData.Data[5].'#text'+"\"+$EventXML.Event.EventData.Data[4].'#text'
    
    if ($Event.ID -eq 4720)
    { 
        $Result.EventDescription = "A user account was created" 
    } 
    if ($Event.ID -eq 4726)
    { 
        $Result.EventDescription = "A user account was deleted" 

    }       
    if ($Event.ID -eq 4732)
    { 
        $Result.EventDescription = "A member was added to a security-enabled local group"
        $Result.SamAccount = (Get-LocalUser -SID $EventXML.Event.EventData.Data[1].'#text').Name
        $Result.AddedRemovedGroup = $EventXML.Event.EventData.Data[2].'#text'
        $Result.SecurityID = (Get-LocalUser -SID $EventXML.Event.EventData.Data[5].'#text').Name
    }
    if ($Event.ID -eq 4733)
    { 
        $Result.EventDescription = "A member was removed from a security-enabled local group"
        $Result.SamAccount = (Get-LocalUser -SID $EventXML.Event.EventData.Data[1].'#text').Name
        $Result.AddedRemovedGroup = $EventXML.Event.EventData.Data[2].'#text'
        $Result.SecurityID = (Get-LocalUser -SID $EventXML.Event.EventData.Data[5].'#text').Name
    }
           
    #Store event data in array
    $Result.EventID = $Event.Id
    $Result.EventTime = $Event.TimeCreated
    $ofs = ', '
    $MemberOf = Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_).name -eq "$env:COMPUTERNAME\$($Result.SamAccount)" }
    $Result.MemberOf = "$MemberOf"
    $ofs = ''
    $EventArray += $Result
}
# Check if the array is empty
if (-not $EventArray)
{
    #Setup blank array headings
    $Result = "" | Select-Object EventTime, EventDescription, EventID, SamAccount, MemberOf, AddedRemovedGroup, SecurityID
    $Result.EventTime = "No data"
    $EventArray += $Result
}
$AccountManagement = $EventArray | ConvertTo-Html -Fragment -As Table  -PreContent "<h2>Accounts Management</h2>"


#########################
## Read FTP Log
#########################
$PathFTP = "C:\inetpub\logs\LogFiles\FTPSVC2\u_ex$(Get-Date -Format "yyMMdd").log" 
#$Ftp_log = Get-Content $PathFTP | ConvertTo-Html -Fragment -As Table -PreContent "<h2>FTP Log</h2>"

$Headers = @((Get-Content -Path $PathFTP -ReadCount 4 -TotalCount 4)[3].split(' ') | Where-Object { $_ -ne '#Fields:' });
$FTP_Log = Import-Csv -Delimiter ' ' -Header $Headers -Path $PathFTP | Where-Object { $_.date -notlike '#*' } | ConvertTo-Html -Fragment -As Table -PreContent "<h2>FTP Log</h2>"


#########################
## Read HTTP Log
#########################


$PathHTTP = "C:\inetpub\logs\LogFiles\W3SVC1\u_ex$(Get-Date -Format "yyMMdd").log" 
#$Ftp_log = Get-Content $PathFTP | ConvertTo-Html -Fragment -As Table -PreContent "<h2>FTP Log</h2>"
If ((test-path $pathHttp)) {
$Headers = @((Get-Content -Path $PathHTTP -ReadCount 4 -TotalCount 4)[3].split(' ') | Where-Object { $_ -ne '#Fields:' });
$HTTP_Log = Import-Csv -Delimiter ' ' -Header $Headers -Path $PathHTTP | Where-Object { $_.date -notlike '#*' } | ConvertTo-Html -Fragment -As Table -PreContent "<h2>HTTP Log</h2>"
}





#########################
## Report / HTML file  ##
##########################
#$OutputFile =  Out-File $Path"\Report-$(Get-Date -Format "MM-dd-yyyy").html"
$Report = ConvertTo-HTML -Body "$ServerName $RDPLogins $SuccessLogins $FailLogins $ObjectAccess $Transcription $ClearLog $AccountManagement $FTP_log $HTTP_log" -Head $header -Title "Computer Information Report" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>" 
$Report | Out-File $Path"\Report-$(Get-Date -Format "MM-dd-yyyy").html"
#out-file ".\$($target).$(get-date -Format "MMddyyyy.HHmmss").txt"






################
## Send Email ##
################

$userName = "#### email address ####@gmail.com"
$password = '#### your password ####'
$pwdSecureString = ConvertTo-SecureString -Force -AsPlainText $password

$Param = @{
    From = "#### email address ####@gmail.com"
    To = "#### email address ####@gmail.com"
    SMTPServer = "smtp.gmail.com"
    UseSsl = $true
    Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $pwdSecureString
}
$Body = Get-Content $Path"\Report-$(Get-Date -Format "MM-dd-yyyy").html"
[array]$attachments = Get-ChildItem "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")" *.txt | Sort CreationTime -Descending -ErrorAction SilentlyContinue
if ($attachments.Count -ne 0) {
    Send-MailMessage  @Param -Body "$Body" -BodyAsHtml -Subject $Sub -Attachments $attachments.FullName
}
else
{
   Send-MailMessage  @Param -Body "$Body" -BodyAsHtml -Subject $Sub 
}

#Remove-Item "$Path\TempReport\$(Get-Date -Format "yyyyMMdd")\*" -Recurse -Force

#Start-Process -FilePath "C:\Users\Administrator\AppData\Local\Scripts\report.exe"
