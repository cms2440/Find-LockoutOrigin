# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
# Check to see if we are currently running "as Administrator"
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
   $scriptpath = $MyInvocation.MyCommand.Definition
   $scriptpaths = "'$scriptPath'"
   # Start the new process
   Start-Process -FilePath PowerShell.exe -Verb runAs -ArgumentList "& $scriptPaths"
   exit
   }

Import-Module ActiveDirectory

# Start of actual code
Remove-Variable user,username,domain -EA SilentlyContinue

#If we're not using Area42 creds, then default to the domain of the creds we are using
if ((whoami) -match ".adm" -and (whoami) -notmatch "area42\\") {
    $domain = (whoami).split("\")[0].toUpper().replace("S","")
    Write-Host "Checking $domain domain"
    #Read-Host
    }
#$domain = "ACC.ACCROOT.DS.AF.SMIL.MIL";$DomainShortName = "ACC"
if (!$domain) {
    $Title = "Select Domain"
    $Message = "Select which domain the account is in"
    $ACC = New-Object System.Management.Automation.Host.ChoiceDescription "&ACC","ACC"
    $AFMC = New-Object System.Management.Automation.Host.ChoiceDescription "&SAFMC","AFMC"
    $AREA42 = New-Object System.Management.Automation.Host.ChoiceDescription "&AREA42","AREA42"
    $Cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Will Abort Script"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($ACC,$AFMC,$Cancel)
    do {
        $result = $host.ui.PromptForChoice($title,$message,$options,0)

        $success = $true
        switch ($result) {
            0 {$domain = "ACC.ACCROOT.DS.AF.SMIL.MIL"}
            1 {$domain = "AFMC.DS.AF.SMIL.MIL"}
            2 {$domain = "area42.afnoapps.usaf.mil"}
            3 {exit}
            default {$success = $false}
            }
        } until ($success -eq $true)
    }
switch ($domain) {
    "ACC" {$DomainShortName = "ACC";$domain = "ACC.ACCROOT.DS.AF.SMIL.MIL"}
    "AFMC" {$DomainShortName = "AFMC";$domain = "AFMC.DS.AF.SMIL.MIL"}
    "AREA42" {$DomainShortName = "AREA42";$domain = "area42.afnoapps.usaf.mil"}
    }
$PDC = (Get-AdDomain -Server $Domain).PDCEmulator
$SourceDCs = @()

#Get the account to find the lockout origin on
$Username = Read-Host "Target SamAccountName (Ex: 1456084571E, 1456084571.adm, `$svc.muhj.doeddatawall)"
#$Username = "chris.steele.adm"
if (!$Username) {
    do {
        try {
            $Username = (Read-Host "Target SamAccountName (Ex: 1456084571E, 1456084571.adm, `$svc.muhj.doeddatawall)").trim()
            $User = Get-ADUser $Username -Server $domain -EA Stop -properties lockedout
            $success = $true
            }
        catch {Write-Host -ForegroundColor Red "Error: $Username does not exist in $DomainShortName.";$success = $false}
        } until ($success)
    }
elseif (!$User) {
    try {
        $User = Get-ADUser $Username -EA Stop -properties lockedout
        }
    catch {Write-Host -ForegroundColor Red "Error: $Username does not exist in $DomainShortName."}
    }

#See if account is currently locked out
if ($user.lockedout) {
    Write-Host -ForegroundColor Green "$username is locked out."
    }
else {
    Write-Host -ForegroundColor Green "$username is not locked out."
    }

#Unlock account
#Has been changed to a variable so the unlock can be on the DC's we are checking the logs on.
#Prompt user if we want to unlock account
$Title = "Unlock Account"
$Message = "Would you like to unlock $username`?"
$Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Unlock account"
$No = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Do NOT unlock account"
$Cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Abort Script"
$options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes,$No,$Cancel)
do {
    $result = $host.ui.PromptForChoice($title,$message,$options,0)

    $success = $true
    switch ($result) {
        0 {$UnlockAccount = $true}
        1 {$UnlockAccount = $false}
        2 {exit}
        default {$success = $false}
        }
    } until ($success -eq $true)

#I just want some spacing
Write-Host ""

##New method to generate DCs to check
$DomainController = [System.DirectoryServices.ActiveDirectory.DomainController]::findOne((new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$Domain)))
$Metadata = $DomainController.GetReplicationMetadata($User)

while ($true) {#Our exit condition will be done via break inside the loop
    Remove-Variable temp -EA SilentlyContinue
    $i = $SourceDCs.count - 1
    $temp = $Metadata.lockouttime.OriginatingServer
    #If theres no data for LockoutTime or the DC is already queued to be checked, then check for last logon
    if ($temp -eq $null -or $SourceDCs -contains $temp) {
        $temp = $Metadata.lastlogontimestamp.OriginatingServer
        #If theres no data for Last Logon or the DC is already queued to be checked, then jsut use the PDC
        if ($temp -eq $null -or $SourceDCs -contains $temp) {
            $temp = $PDC
            }
        }
    #This is our exit condition
    #If this is a DC we already queued up, we'll just hit an infinite loop, so break.
    if ($SourceDCs -contains $temp) {
        if ($SourceDCs -notcontains $PDC) {$SourceDCs += $PDC}
        break
        }
    #Add the originating server if it's not already queued to be checked.
    if ($SourceDCs -notcontains $temp) {$SourceDCs += $temp}
    try {
        $DomainController = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController((new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer",$temp)))
        $Metadata = $DomainController.GetReplicationMetadata((Get-ADUser $Username -Server ($DomainController.name)))
        }
    #If we can't get the metadata for the server, then just end the queue with the PDC
    catch {
        if ($SourceDCs -notcontains $PDC) {$SourceDCs += $PDC}
        break
        }
    }

#Give a warning message in case we won't be very helpful
if (($SourceDCs.Count -eq 2 -and $SourceDCs -match "JUMJ") -or $SourceDCs.count -eq 1) {
    Write-Host -ForegroundColor Magenta "We're only checking the PDC.  Don't get your hopes up."
    }

# Query the security event log
foreach ($DC in $SourceDCs) {
    if (-not $DC) {continue}    
    $DCoutput = $DC.split(".")[0]
    if ($DC -match "JUMJ") {
        Write-Host -ForegroundColor Magenta "You can try RDCing into $DCoutput (Gunter), but it's extremely rare that this was the actual DC performing the lockout."
        continue
        }

    if ($UnlockAccount) {Unlock-ADAccount $Username -Server $DC -ErrorAction SilentlyContinue}

    Write-Host "Checking $DCoutput Event Logs"
    if ($DC -eq $PDC) {
        Write-Host -ForegroundColor Cyan "This is the PDC.  We're going to be trying until we get its eventlog.  Close this window when you don't want to try anymore."
        }
    # Build the parameters to pass to Get-WinEvent
    $GweParams = @{
        ‘Computername’ = $DC
        ‘LogName’ = ‘Security’
        ‘FilterXPath’ = "*[System[EventID=4740] and EventData[Data[@Name='TargetUserName']='$Username']]"
        }
        
    #Only try each DC 5 time until we get its event logs, unless its the PDC in which we try til we get them.
    for ($i = 0;($DC -eq $PDC) -or ($i -lt 5);$i++) {
        try {
            #Write Computer Name that caused lockout
            $Events = @()
            $Events += Get-WinEvent @GweParams -ErrorAction stop
            Write-Host -ForegroundColor Green "Computer" -NoNewline
            if ($Events.count -gt 1) {Write-Host -ForegroundColor Green "s" -NoNewline}
            Write-Host -ForegroundColor Green  " causing lockout:" ($Events | foreach {"`n" + $_.Properties[1].Value + " : " + $_.TimeCreated}) #(($Events | select -First 1).Properties[1].Value)
            Write-Host "Computer has been found.  You can close this window, or let it continue for $#!+s and Giggles."
            Read-Host -Prompt "Press Enter to continue..."
            break
            }
        catch {
            #No events were found that match the specified selection criteria.
            if (($error[0].FullyQualifiedErrorId) -eq "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand") {
                Write-Host "Connected to $DCoutput, but Event Log not found."
                break
                }
            #The RPC server is unavailable
            elseif (($error[0].FullyQualifiedErrorId) -eq "System.Diagnostics.Eventing.Reader.EventLogException,Microsoft.PowerShell.Commands.GetWinEventCommand") {
                If (($DC -eq $PDC) -or ($i -ne 4)) {
                    Write-Host -ForegroundColor Red "RPC failure connecting to $DCoutput.  Attempting to contact $DCoutput again..."
                    }
                else {
                    Write-Host -ForegroundColor Red "Could not connect to DC.  You'll have to manually RDC into the server and check for Security Event 4740"
                    }
                }
            else {
                Write-Host -ForegroundColor Red $error[0]
                }
            }
        }
    Write-Host
    }

Read-Host -Prompt "Press Enter to continue..."
