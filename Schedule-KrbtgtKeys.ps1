<#
.SYNOPSIS
	This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner

.VERSION
	v1.0 based on v2.5 of New-KrbtgtKeys.ps1, 2020-02-17
	
.AUTHORS
	Original Script New-KrbtgtKeys.ps1:
	Initial Script/Thoughts.................: Jared Poeppelman, Microsoft
	Script Re-Written/Enhanced..............: Jorge de Almeida Pinto [MVP Enterprise Mobility And Security, EMS]

	This Script Schedule-KrbtgtKeys.ps1:
	Script modified to run on a schedule by: Martin Hill

.DESCRIPTION
    This PoSH script provides the following functions:
	- Single Password Reset for the KrbTgt account in use by RWDCs in a the local AD domain, using the PROD KrbTgt accounts
		- Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
		* From a security perspective as mentioned in https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/
		* From an AD recovery perspective as mentioned in https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
	- Logfile of each run is saved in the running location (Get-Location) and can be sent via email (see email/smtp configuration on line 93)
	
	Behavior:
	- You will get a list of all RWDCs, and alls RODCs if applicable, in the targeted local AD domain that are available/reachable
		or not
    -It uses PROD/REAL krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted PROD/REAL krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the pwdLastSet
		attribute value of the same PROD/REAL krbtgt account on the originating RWDC
		* For RWDCs it uses the PROD/REAL krbtgt account "krbtgt" (All RWDCs)
		* For RODCs it uses the PROD/REAL krbtgt account "krbtgt_<Numeric Value>" (RODC Specific)
    -When performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an
		RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
	- When targeting the krbtgt account in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO
		and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those
		do not use the krbtg account in use by the RWDCs and also do not store/cache its password.
	- The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object
		that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication.
		Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the "source" server is
		determined. In case the RODC is not available or its "source" server is not available, the RWDC with the PDC FSMO is used to reset
		the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if
		not available the check is skipped

.KNOWN ISSUES/BUGS
	- Although this script can be used in an environment with Windows Server 2000/2003 RWDCs, it is NOT supported to do this. Windows Server
		2000/2003 RWDCs cannot do KDC PAC validation using the previous (N-1) krbtgt password. Those RWDCs only attempt that with the current
		(N) password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed, authentication issues could be
		experienced because the target server gets a PAC validation error when asking the KDC (domain controller) to validate the KDC signature
		of the PAC that is inside the service ticket that was presented by the client to the server. This problem would potentially persist
		for the lifetime of the service ticket(s). It is also highly recommended NOT to use products that have reached their end support.
		Please upgrade as soon as possible.
	- This is not related to this script. When increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt
		Account will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new keys
		for DES, RC4, AES128, AES256!

.RELEASE NOTES
	v1.0 based on Original Script New-KrbtgtKeys.ps1 v2.5, 2020-02-17, Jorge de Almeida Pinto [MVP-EMS]:

.NOTES
	- To execute this script, the account running the script MUST be a member of the "Domain Admins" or Administrators group in the
		targeted AD domain.
	- If the account used is from another AD domain in the same AD forest, then the account running the script MUST be a member of the
	    "Enterprise Admins" group in the AD forest or Administrators group in the targeted AD domain. For all AD domains in the same
	    AD forest, membership of the "Enterprise Admins" group is easier as by default it is a member of the Administrators group in
	    every AD domain in the AD forest
	- If the account used is from another AD domain in another AD forest, then the account running the script MUST be a member of the
	    "Administrators" group in the targeted AD domain. This also applies to any other target AD domain in that same AD forest
	- This is due to the reset of the password for the targeted KrbTgt account(s) and forcing (single object) replication between DCs
	- Testing "Domain Admins" membership is done through "IsInRole" method as the group is domain specific
	- Testing "Enterprise Admins" membership is done through "IsInRole" method as the group is forest specific
	- Testing "Administrators" membership cannot be done through "IsInRole" method as the group exist in every AD domain with the same
		SID. To still test for required permissions in that case, the value of the Description attribute of the KRBTGT account is copied
		into the DisplayName attribute and cleared afterwards. If both those actions succeed it is proven the required permissions are
		in place!
#>

### Definition Of Some Constants
$execDateTime = Get-Date
$execDateTimeYEAR = $execDateTime.Year
$execDateTimeMONTH = $execDateTime.Month
$execDateTimeDAY = $execDateTime.Day
$execDateTimeHOUR = $execDateTime.Hour
$execDateTimeMINUTE = $execDateTime.Minute
$execDateTimeSECOND = $execDateTime.Second
$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)
$adRunningUserAccount = $ENV:USERDOMAIN + "\" + $ENV:USERNAME
$currentScriptFolderPath = Get-Location
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
[string]$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Reset-KrbTgt-Password-For-RWDCs-And-RODCs.log")
$modeOfOperationNr = 4
$targetKrbTgtAccountNr = 1

### Email Settings to Define Manually
$emailFrom = "KrbTgt@server.local" #Enter the email from address 
$smtp = "smtp.server.local" #Enter the smtp server address
$smtpPort = 25 #Enter the smtp server port e.g. 25 or 587
$emailTo = "securityteam@server.local" #Enter the email to address
$body = "Attached is the Krbtgt Scheduled Reset Log File" #Enter whatever you want to appear in the body of the email
$attachment = $logFilePath #Attach the script logfile for the current run

### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
    If($dataToLog -eq ""){
    Out-File -filepath "$logFilePath" -append -inputObject "$dataToLog"
    } Else {
	Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
    }
}

### FUNCTION: Send Log File Via Email
Function Email($emailSub) {
    Send-MailMessage -SmtpServer $smtp -From $emailFrom -To $emailTo -Subject $emailSub -Body $body -Attachments $attachment -ErrorAction SilentlyContinue -ErrorVariable emailError
    If ($emailError){
    Logging "Warning: Unable to send the log file by email, please check the email settings on line 93"
    Logging "Send-MailMessage -SmtpServer $smtp -From $emailFrom -To $emailTo -Subject $emailSub -Body $body -Attachments $attachment"
    }
}

### FUNCTION: Test The Port Connection
Function portConnectionCheck($fqdnServer,$port,$timeOut) {
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer,$port,$null,$null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut,$false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return
	} Else {
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return
		} Else {
			Return
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($PoSHModule) {
	$retValue = $null
	If(@(Get-Module | Where-Object{$_.Name -eq $PoSHModule}).count -eq 0) {
		If(@(Get-Module -ListAvailable | Where-Object{$_.Name -eq $PoSHModule} ).count -ne 0) {
			Import-Module $PoSHModule
			Logging "PoSH Module '$PoSHModule' Has Been Loaded..."
			$retValue = "HasBeenLoaded"
		} Else {
			Logging "PoSH Module '$PoSHModule' Is Not Available To Load..."
			$retValue = "NotAvailable"
		}
	} Else {
		Logging "PoSH Module '$PoSHModule' Already Loaded..."
		$retValue = "AlreadyLoaded"
	}
	Return $retValue
}

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function confirmPasswordIsComplex($pwd) {
	Process {
		$criteriaMet = 0
		
		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[A-Z]') {$criteriaMet++}
		
		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[a-z]') {$criteriaMet++}
		
		# Numeric Characters (0 through 9)
		If ($pwd -match '\d') {$criteriaMet++}
		
		# Special Chracters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($pwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}
		
		# Check If It Matches Default Windows Complexity Requirements
		If ($criteriaMet -lt 3) {Return $false}
		If ($pwd.Length -lt 8) {Return $false}
		Return $true
	}
}

### FUNCTION: Generate New Complex Password
Function generateNewComplexPassword([int]$passwordNrChars) {
	Process {
		$iterations = 0
        Do {
			If ($iterations -ge 20) {
				Logging "  --> Complex password generation failed after '$iterations' iterations..."
				Logging ""
				Email "Krbtgt Error: Complex password generation failed"
				EXIT
			}
			$iterations++
			$pwdBytes = @()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
                $pwdBytes += $byte[0]
			}
			While ($pwdBytes.Count -lt $passwordNrChars)
				$pwd = ([char[]]$pwdBytes) -join ''
			} 
        Until (confirmPasswordIsComplex $pwd)
        Return $pwd
	}
}

### FUNCTION: Reset Password Of AD Account
Function setPasswordOfADAccount($targetedADdomainRWDC, $krbTgtSamAccountName, $localADforest, $remoteCredsUsed, $adminCreds) {
	# Retrieve The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBefore = $null
	If ($localADforest -eq $true) {
		$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDC
	}
    # Get The DN Of The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforeDN = $null
	$krbTgtObjectBeforeDN = $krbTgtObjectBefore.DistinguishedName
	
	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforePwdLastSet = $null
	$krbTgtObjectBeforePwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectBefore.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
	
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$metadataObjectBefore = $null
	If ($localADforest -eq $true) {
		$metadataObjectBefore = Get-ADReplicationAttributeMetadata $krbTgtObjectBeforeDN -Server $targetedADdomainRWDC
	}
	$metadataObjectBeforeAttribPwdLastSet = $null
	$metadataObjectBeforeAttribPwdLastSet = $metadataObjectBefore | Where-Object{$_.AttributeName -eq "pwdLastSet"}
	$orgRWDCNTDSSettingsObjectDNBefore = $null
	$orgRWDCNTDSSettingsObjectDNBefore = $metadataObjectBeforeAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
	$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN = $null
	If ($orgRWDCNTDSSettingsObjectDNBefore) {			
		# Strip "CN=NTDS Settings," To End Up With The Server Object DN
		$orgRWDCServerObjectDNBefore = $null
		$orgRWDCServerObjectDNBefore = $orgRWDCNTDSSettingsObjectDNBefore.SubString(("CN=NTDS Settings,").Length)
		
		# Connect To The Server Object DN
		$orgRWDCServerObjectObjBefore = $null
		If ($localADforest -eq $true) {
			$orgRWDCServerObjectObjBefore = ([ADSI]"LDAP://$targetedADdomainRWDC/$orgRWDCServerObjectDNBefore")
		}
		$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObjBefore.dnshostname[0]
	} Else {
		$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
	}
	$metadataObjectBeforeAttribPwdLastSetOrgTime = $null
	$metadataObjectBeforeAttribPwdLastSetOrgTime = Get-Date $($metadataObjectBeforeAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$metadataObjectBeforeAttribPwdLastSetVersion = $null
	$metadataObjectBeforeAttribPwdLastSetVersion = $metadataObjectBeforeAttribPwdLastSet.Version
	
	Logging "  --> RWDC To Reset Password On.............: '$targetedADdomainRWDC'"
	Logging "  --> sAMAccountName Of KrbTgt Account......: '$krbTgtSamAccountName'"
	Logging "  --> Distinguished Name Of KrbTgt Account..: '$krbTgtObjectBeforeDN'"
	
	# Specify The Number Of Characters The Generate Password Should Contain
	$passwordNrChars = 64
	Logging "  --> Number Of Chars For Pwd Generation....: '$passwordNrChars'"
	
	# Generate A New Password With The Specified Length (Text)
	$newKrbTgtPassword = $null
	$newKrbTgtPassword = (generateNewComplexPassword $passwordNrChars).ToString()
	
	# Convert The Text Based Version Of The New Password To A Secure String
	$newKrbTgtPasswordSecure = $null
	$newKrbTgtPasswordSecure = ConvertTo-SecureString $newKrbTgtPassword -AsPlainText -Force
	
	# Try To Set The New Password On The Targeted KrbTgt Account And If Not Successfull Throw Error
	Try {
		If ($localADforest -eq $true) {
			Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDC -Reset -NewPassword $newKrbTgtPasswordSecure
		}
	} Catch {
		Logging ""
		Logging "  --> Setting the new password for [$krbTgtObjectBeforeDN] FAILED on RWDC [$targetedADdomainRWDC]!..."
		Logging ""
	}

	# Retrieve The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfter = $null
	If ($localADforest -eq $true) {
		$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDC
	}
	# Get The DN Of The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfterDN = $null
	$krbTgtObjectAfterDN = $krbTgtObjectAfter.DistinguishedName
	
	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfterPwdLastSet = $null
	$krbTgtObjectAfterPwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectAfter.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
	
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object AFTER THE PASSWORD SET
	$metadataObjectAfter = $null
	If ($localADforest -eq $true) {
		$metadataObjectAfter = Get-ADReplicationAttributeMetadata $krbTgtObjectAfterDN -Server $targetedADdomainRWDC
	}
	$metadataObjectAfterAttribPwdLastSet = $null
	$metadataObjectAfterAttribPwdLastSet = $metadataObjectAfter | Where-Object{$_.AttributeName -eq "pwdLastSet"}
	$orgRWDCNTDSSettingsObjectDNAfter = $null
	$orgRWDCNTDSSettingsObjectDNAfter = $metadataObjectAfterAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
	$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN = $null
	If ($orgRWDCNTDSSettingsObjectDNAfter) {			
		# Strip "CN=NTDS Settings," To End Up With The Server Object DN
		$orgRWDCServerObjectDNAfter = $null
		$orgRWDCServerObjectDNAfter = $orgRWDCNTDSSettingsObjectDNAfter.SubString(("CN=NTDS Settings,").Length)
		
		# Connect To The Server Object DN
		$orgRWDCServerObjectObjAfter = $null
		If ($localADforest -eq $true) {
			$orgRWDCServerObjectObjAfter = ([ADSI]"LDAP://$targetedADdomainRWDC/$orgRWDCServerObjectDNAfter")
		}
		$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObjAfter.dnshostname[0]
	} Else {
		$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
	}
	$metadataObjectAfterAttribPwdLastSetOrgTime = $null
	$metadataObjectAfterAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAfterAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$metadataObjectAfterAttribPwdLastSetVersion = $null
	$metadataObjectAfterAttribPwdLastSetVersion = $metadataObjectAfterAttribPwdLastSet.Version
	Logging ""
	Logging "  --> Previous Password Set Date/Time.......: '$krbTgtObjectBeforePwdLastSet'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Password Set Date/Time............: '$krbTgtObjectAfterPwdLastSet'"
	}
	Logging ""
	Logging "  --> Previous Originating RWDC.............: '$metadataObjectBeforeAttribPwdLastSetOrgRWDCFQDN'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Originating RWDC..................: '$metadataObjectAfterAttribPwdLastSetOrgRWDCFQDN'"
	}
	Logging ""
	Logging "  --> Previous Originating Time.............: '$metadataObjectBeforeAttribPwdLastSetOrgTime'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Originating Time..................: '$metadataObjectAfterAttribPwdLastSetOrgTime'"
	}
	Logging ""
	Logging "  --> Previous Version Of Attribute Value...: '$metadataObjectBeforeAttribPwdLastSetVersion'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Version Of Attribute Value........: '$metadataObjectAfterAttribPwdLastSetVersion'"
	}

	# Check And Confirm If The Password Value Has Been Updated By Comparing The Password Last Set Before And After The Reset
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging ""
		Logging "  --> The new password for [$krbTgtObjectAfterDN] HAS BEEN SET on RWDC [$targetedADdomainRWDC]!..."
		Logging ""
	}
}

### FUNCTION: Replicate Single AD Object
# INFO: https://msdn.microsoft.com/en-us/library/cc223306.aspx
Function replicateSingleADObject($sourceDCNTDSSettingsObjectDN, $targetDCFQDN, $objectDN, $contentScope, $localADforest, $remoteCredsUsed, $adminCreds) {
	# Define And Target The root DSE Context
	$rootDSE = $null
	If ($localADforest -eq $true) {
		$rootDSE = [ADSI]"LDAP://$targetDCFQDN/rootDSE"
	}
	# Perform A Replicate Single Object For The Complete Object
	If ($contentScope -eq "Full") {
		$rootDSE.Put("replicateSingleObject",$sourceDCNTDSSettingsObjectDN+":"+$objectDN)
	}
	# Perform A Replicate Single Object For Obnly The Secrets Of The Object
	If ($contentScope -eq "Secrets") {
		$rootDSE.Put("replicateSingleObject",$sourceDCNTDSSettingsObjectDN+":"+$objectDN+":SECRETS_ONLY")
	}	
	# Commit The Change To The Operational Attribute
	$rootDSE.SetInfo()
}

### FUNCTION: Check AD Replication Convergence
Function checkADReplicationConvergence($targetedADdomainFQDN, $targetedADdomainSourceRWDCFQDN, $targetObjectToCheckDN, $listOfDCsToCheckObjectOnStart, $listOfDCsToCheckObjectOnEnd, $modeOfOperationNr, $localADforest, $remoteCredsUsed, $adminCreds) {
	# Determine The Starting Time
	$startDateTime = Get-Date
	
	# Counter
	$c = 0
	
	# Boolean To Use In The While Condition
	$continue = $true
	
	# The Delay In Seconds Before The Next Check Iteration
	$delay = 0.1
	
	While($continue) {
		$c++
		Logging ""
		Logging "====================================== CHECKING REPLICATION: PASS NUMBER $c ======================================"
		Logging ""
		
		# Wait For The Duration Of The Configured Delay Before Trying Again
		Start-Sleep $delay
		
		# Variable Specifying The Object Is In Sync
		$replicated = $true
		
		# For Each DC To Check On The Starting List With All DCs To Check Execute The Following...
		ForEach ($dcToCheck in $listOfDCsToCheckObjectOnStart) {
			# HostName Of The DC To Check
			$dcToCheckHostName = $null
			$dcToCheckHostName = $dcToCheck."Host Name"
			
			# Is The DC To Check Also The PDC?
			$dcToCheckIsPDC = $null
			$dcToCheckIsPDC = $dcToCheck.PDC
			
			# SiteName Of The DC To Check
			$dcToCheckSiteName = $null
			$dcToCheckSiteName = $dcToCheck."Site Name"
			
			# Type (RWDC Or RODC) Of The DC To Check
			$dcToCheckDSType = $null
			$dcToCheckDSType = $dcToCheck."DS Type"
			
			# IP Address Of The DC To Check
			$dcToCheckIPAddress = $null
			$dcToCheckIPAddress = $dcToCheck."IP Address"
			
			# Reachability Of The DC To Check
			$dcToCheckReachability = $null
			$dcToCheckReachability = $dcToCheck.Reachable
			
			# DSA DN Of The Source RWDC Of The DC To Check
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $null
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $dcToCheck."Source RWDC DSA"

			# When Running Mode 4 (Using PROD/REAL KrbTgt Accounts)
			If ($modeOfOperationNr -eq 4) {
				# Retrieve The Object From The Source Originating RWDC
				$objectOnSourceOrgRWDC = $null
				If ($localADforest -eq $true) {
					$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN
				}
				# Retrieve The Password Last Set Of The Object On The Source Originating RWDC
				$objectOnSourceOrgRWDCPwdLastSet = $null
				$objectOnSourceOrgRWDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnSourceOrgRWDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			}

			# When The DC To Check Is Also The Source (Originating) RWDC
			If ($dcToCheckHostName -eq $targetedADdomainSourceRWDCFQDN) {
				Logging "  - Contacting the source read/write domain controller [$($dcToCheckHostName.ToUpper())]......"
				Logging "     * [$dcToCheckHostName] is alive!"
				
				If ($modeOfOperationNr -eq 4) {
					Logging "     * The password for Object [$targetObjectToCheckDN] exists in the AD database"
                    Logging "     * The timestamp on the password is [$objectOnSourceOrgRWDCPwdLastSet]"
				}
				Logging ""
				CONTINUE
			}
			
			Logging "  - Contacting domain controller [$($dcToCheckHostName.ToUpper())]......"
			If ($dcToCheckReachability) {
				# When The DC To Check Is Reachable
                Logging "     * [$dcToCheckHostName] is alive!"
				
				# When The DC To Check Is Not The Source (Originating) RWDC
				If ($dcToCheckHostName -ne $targetedADdomainSourceRWDCFQDN) {
					# As The DSA DN Used The DSA DN Of The Source (Originating) RWDC Of The DC Being Checked
					$sourceDCNTDSSettingsObjectDN = $dcToCheckSourceRWDCNTDSSettingsObjectDN
					
					# For Mode 4
					If ($modeOfOperationNr -eq 4) {
						# If The DC Being Checked Is An RWDC Perform A Full Replicate Single Object
						If ($dcToCheckDSType -eq "Read/Write") {
							$contentScope = "Full"
						}
						
						# If The DC Being Checked Is An RODC Perform A Partial Replicate Single Object (Secrets Only)
						If ($dcToCheckDSType -eq "Read-Only") {
							$contentScope = "Secrets"
						}
					}
					
					# Execute The Replicate Single Object Function For The Targeted Object To Check
					replicateSingleADObject $sourceDCNTDSSettingsObjectDN $dcToCheckHostName $targetObjectToCheckDN $contentScope $localADforest $remoteCredsUsed $adminCreds
				}
				
				# For 4 From The DC to Check Retrieve The AD Object Of The Targeted KrbTgt Account (And Its Password Last Set) That Had Its Password Reset On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 4) {
					# Retrieve The Object From The Target DC
					$objectOnTargetDC = $null
					If ($localADforest -eq $true) {
						$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName
					}
					# Retrieve The Password Last Set Of The Object On The Target DC
					$objectOnTargetDCPwdLastSet = $null
					$objectOnTargetDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnTargetDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
				}
			} Else {
				# When The DC To Check Is Not Reachable
				Logging "     * [$dcToCheckHostName] is NOT reachable..."
			}
			
			If ($dcToCheckReachability) {
				# When The DC To Check Is Reachable

				If ($objectOnTargetDCPwdLastSet -eq $objectOnSourceOrgRWDCPwdLastSet) {
					# If The Target Object Password Last Set Does Match With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 4 Only
					If ($modeOfOperationNr -eq 4) {
						Logging "     * The password for Object [$targetObjectToCheckDN] exists in the AD database"
                        Logging "     * The timestamp on the password is [$objectOnTargetDCPwdLastSet]"
					}
					Logging ""
					
					# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
					If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {
						# Define The Columns For This DC To Be Filled In
						$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Host Name" = $dcToCheckHostName
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj.PDC = $null
						$listOfDCsToCheckObjectOnEndObj.PDC = $dcToCheckIsPDC
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Site Name" = $dcToCheckSiteName
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
						$listOfDCsToCheckObjectOnEndObj."DS Type" = $dcToCheckDSType
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
						$listOfDCsToCheckObjectOnEndObj."IP Address" = $dcToCheckIPAddress
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj.Reachable = $null
						$listOfDCsToCheckObjectOnEndObj.Reachable = $dcToCheckReachability
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj.Time = ("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds)
						
						# Add The Row For The DC To The Table
						$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
					}
				} Else {
					# If The Target Object To Check Does Not Exist Or Its Password Last Set Does Not Match (Yet) With The Password Last Set Of The Object On The Source (Originating) RWDC
                    If ($modeOfOperationNr -eq 4) {
						Logging "     * The new password for Object [$targetObjectToCheckDN] does NOT exist yet in the AD database"
					}
					Logging ""
					
					# Variable Specifying The Object Is Not In Sync
					$replicated = $false
				}
			} Else {
				# When The DC To Check Is Not Reachable
				Logging "     * Unable to connect to DC and check for Object [$targetObjectToCheckDN]..."
				Logging ""
				
				# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
				If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {
					# Define The Columns For This DC To Be Filled In
					$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
					$listOfDCsToCheckObjectOnEndObj."Host Name" = $dcToCheckHostName
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj.PDC = $null
					$listOfDCsToCheckObjectOnEndObj.PDC = $dcToCheckIsPDC
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
					$listOfDCsToCheckObjectOnEndObj."Site Name" = $dcToCheckSiteName
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
					$listOfDCsToCheckObjectOnEndObj."DS Type" = $dcToCheckDSType
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
					$listOfDCsToCheckObjectOnEndObj."IP Address" = $dcToCheckIPAddress
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj.Reachable = $null
					$listOfDCsToCheckObjectOnEndObj.Reachable = $dcToCheckReachability
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
					$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj.Time = "<Fail>"
					
					# Add The Row For The DC To The Table
					$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
				}
			}
		}

		# If The Object Is In Sync
		If ($replicated) {
			# Do Not Continue For The DC That Is Being Checked
			$continue = $false
		}
	}

	# Determine The Ending Time
	$endDateTime = Get-Date
	
	# Calculate The Duration
	$duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
	Logging ""
	Logging "  --> Start Time......: $(Get-Date $startDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	Logging "  --> End Time........: $(Get-Date $endDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	Logging "  --> Duration........: $duration Seconds"
	Logging ""

	# Sort The Ending List With All DCs That Were Checked
	$listOfDCsToCheckObjectOnEnd = $listOfDCsToCheckObjectOnEnd | Sort-Object -Property @{Expression = "Time"; Descending = $False}
	Logging ""
	Logging "List Of DCs In AD Domain '$targetedADdomainFQDN' And Their Timing..."
	Logging ""
	Logging "$($listOfDCsToCheckObjectOnEnd | Out-String)"
	Logging ""
}

### Loading Required PowerShell Modules
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
Logging "LOADING REQUIRED POWERSHELL MODULES..."
Logging ""

# Try To Load The Required PowerShell Module. Abort Script If Not Available
$poshModuleAD = loadPoSHModules ActiveDirectory
If ($poshModuleAD -eq "NotAvailable") {
	Logging ""
	Email "Krbtgt Error: ActiveDirectory PowerShell Module Not Available"
	EXIT
}
Logging ""

# Try To Load The Required PowerShell Module. Abort Script If Not Available
$poshModuleGPO = loadPoSHModules GroupPolicy
If ($poshModuleGPO -eq "NotAvailable") {
	Logging ""
	Email "Krbtgt Error: GroupPolicy PowerShell Module Not Available"
	EXIT
}
Logging ""

# Retrieve The AD Domain And AD Forest Of The Computer Where The Script Is Executed
$currentADDomainOfLocalComputer = $null
$currentADDomainOfLocalComputer = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
$currentADForestOfLocalComputer = $null
$currentADForestOfLocalComputer = (Get-ADDomain $currentADDomainOfLocalComputer).Forest

# Ask Which AD Forest To Target
Logging "The AD forest to be targeted is the current AD forest: $currentADForestOfLocalComputer"
$targetedADforestFQDN = $null
$targetedADforestFQDN = $currentADForestOfLocalComputer

# Validate The Specified AD Forest via DNS
$adForestValidity = $false
Try {
	[System.Net.Dns]::gethostentry($targetedADforestFQDN) | Out-Null
	$adForestValidity = $true
} Catch {
	$adForestValidity = $false
}
$localADforest = $true
$adForestLocation = "Local"
Logging ""
Logging "Checking Resolvability of the specified $adForestLocation AD forest '$targetedADforestFQDN' through DNS..."
If ($adForestValidity -eq $true) {
	# If The AD Forest Is Resolvable And Therefore Exists, Continue
	Logging ""
	Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' is resolvable through DNS!"
	Logging ""
	Logging "Continuing Script..."
	Logging ""
} Else {
	# If The AD Forest Is Not Resolvable And Therefore Does Not Exists, Abort
	Logging ""
	Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' IS NOT resolvable through DNS!"
	Logging ""
	Logging "Aborting Script..."
	Logging ""
	Email "Krbtgt Error: The AD forest IS NOT resolvable through DNS!"
	EXIT
}

# Validate The Specified AD Forest Is Accessible. If it is the local AD forest then it is accessible. If it is a remote AD forest and a (forest) trust is in place, then it is accessible. If it is a remote AD forest and a (forest) trust is NOT in place, then it is NOT accessible.
$adForestAccessibility = $false
# Test To See If The AD Forest Is Accessible
Try {
	# Retrieve The Nearest RWDC In The Forest Root AD Domain
	$nearestRWDCInForestRootADDomain = $null
	$nearestRWDCInForestRootADDomain = (Get-ADDomainController -DomainName $targetedADforestFQDN -Discover).HostName[0]
	
	# Retrieve Information About The AD Forest
	$thisADForest = $null
	$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain
	$adForestAccessibility = $true
	$remoteCredsUsed = $false
} Catch {
	$adForestAccessibility = $false
	$remoteCredsUsed = $true
}
Logging ""
Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
If ($adForestAccessibility -eq $true) {
	# If The AD Forest Is Accessible, Continue
	Logging ""
	Logging "The specified AD forest '$targetedADforestFQDN' is accessible!"
	Logging ""
	Logging "Continuing Script..."
	Logging ""
} Else {
    # If The AD Forest Is NOT Accessible, Ask For Credentials
    Logging ""
    Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!"
    Logging ""
    Logging "Please re-schedule the script and provide the correct credentials to connect to the AD forest..."
    Logging ""
    Logging "Aborting Script..."
    Logging ""
	Email "Krbtgt Error: The AD Forest Is NOT Accessible, Please Check The Credentials"
    EXIT
}

### All Modes - Selecting The Target AD Domain
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
Logging "SELECT THE TARGET AD DOMAIN..."
Logging ""

# Retrieve Root AD Domain Of The AD Forest
$rootADDomainInADForest = $null
$rootADDomainInADForest = $thisADForest.RootDomain

# Retrieve All The AD Domains In The AD Forest
$listOfADDomainsInADForest = $null
$listOfADDomainsInADForest = $thisADForest.Domains

# Retrieve The DN Of The Partitions Container In The AD Forest
$partitionsContainerDN = $null
$partitionsContainerDN = $thisADForest.PartitionsContainer

# Retrieve The Mode/Functional Level Of The AD Forest
$adForestMode = $null
$adForestMode = $thisADForest.ForestMode

# Define An Empty List/Table That Will Contain All AD Domains In The AD Forest And Related Information
$tableOfADDomainsInADForest = @()
Logging "Forest Mode/Level...: $adForestMode"

# Set The Counter To Zero
$nrOfDomainsInForest = 0

# Execute For All AD Domains In The AD Forest
$listOfADDomainsInADForest | ForEach-Object{
	# Increase The Counter
	$nrOfDomainsInForest += 1
	
	# Get The FQDN Of The AD Domain
	$domainFQDN = $null
	$domainFQDN = $_
	
	# Retrieve The Nearest RWDC In The AD Domain
	$nearestRWDCInADDomain = $null
	$nearestRWDCInADDomain = (Get-ADDomainController -DomainName $domainFQDN -Discover).HostName[0]
	
	# Retrieve The Object Of The AD Domain From AD
	$domainObj = $null
	Try {
		If ($localADforest -eq $true) {
			$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain
		}
	} Catch {
		$domainObj = $null
	}
	
	# Define The Columns For This AD Domain To Be Filled In
	$tableOfADDomainsInADForestObj = "" | Select-Object Name,DomainSID,IsRootDomain,DomainMode,IsCurrentDomain,IsAvailable,PDCFsmoOwner,NearestRWDC
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.Name = $null
	$tableOfADDomainsInADForestObj.Name = $domainFQDN
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.DomainSID = $null
	$tableOfADDomainsInADForestObj.DomainSID = $domainObj.DomainSID.Value
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.IsRootDomain = $null
	If ($rootADDomainInADForest -eq $domainFQDN) {
		$tableOfADDomainsInADForestObj.IsRootDomain = "TRUE"
	} Else {
		$tableOfADDomainsInADForestObj.IsRootDomain = "FALSE"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.DomainMode = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.DomainMode = $domainObj.DomainMode
	} Else {
		$tableOfADDomainsInADForestObj.DomainMode = "AD Domain Is Not Available"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.IsCurrentDomain = $null
	If ($domainFQDN -eq $currentADDomainOfLocalComputer) {
		$tableOfADDomainsInADForestObj.IsCurrentDomain = "TRUE"
	} Else {
		$tableOfADDomainsInADForestObj.IsCurrentDomain = "FALSE"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.IsAvailable = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.IsAvailable = "TRUE"
	} Else {
		$tableOfADDomainsInADForestObj.IsAvailable = "FALSE"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.PDCFsmoOwner = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.PDCFsmoOwner = $domainObj.PDCEmulator
	} Else {
		$tableOfADDomainsInADForestObj.PDCFsmoOwner = "AD Domain Is Not Available"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.NearestRWDC = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.NearestRWDC = $nearestRWDCInADDomain
	} Else {
		$tableOfADDomainsInADForestObj.NearestRWDC = "AD Domain Is Not Available"
	}
	
	# Add The Row For The AD Domain To The Table
	$tableOfADDomainsInADForest += $tableOfADDomainsInADForestObj
}

# Display The List And Amount Of AD Domains
Logging ""
Logging "List Of AD Domains In AD Forest '$rootADDomainInADForest'..."
Logging ""
Logging "$($tableOfADDomainsInADForest | Out-String)"
Logging "  --> Found [$nrOfDomainsInForest] AD Domain(s) in the AD forest '$rootADDomainInADForest'..."
Logging ""

# Use The AD Domain Of The Local Computer
If ($targetedADdomainFQDN -eq "" -Or $null -eq $targetedADdomainFQDN) {
	$targetedADdomainFQDN = $currentADDomainOfLocalComputer
}
Logging ""
Logging "  --> Selected AD Domain: '$targetedADdomainFQDN'..."

# Validate The Chosen AD Domain Against The List Of Available AD Domains To See If It Does Exist In The AD Forest
$adDomainValidity = $false
$listOfADDomainsInADForest | ForEach-Object{
	$domainFQDN = $null
	$domainFQDN = $_
	If ($domainFQDN -eq $targetedADdomainFQDN) {
		$adDomainValidity = $true
	}
}
Logging ""
Logging "Checking existence of the specified AD domain '$targetedADdomainFQDN' in the AD forest '$rootADDomainInADForest'..."
If ($adDomainValidity -eq $true) {
	# If The AD Domain Is Valid And Therefore Exists, Continue
	Logging ""
	Logging "The specified AD domain '$targetedADdomainFQDN' exists in the AD forest '$rootADDomainInADForest'!"
	Logging ""
	Logging "Continuing Script..."
	Logging ""
} Else {
	# If The AD Domain Is Not Valid And Therefore Does Not Exist, Abort
	Logging ""
	Logging "The specified AD domain '$targetedADdomainFQDN' DOES NOT exist in the AD forest '$rootADDomainInADForest'!"
	Logging ""
	Logging "Please troubleshoot the state of the AD Forest '$rootADDomainInADForest'..."
	Logging ""
	Logging "Aborting Script..."
	Logging ""
	Email "Krbtgt Error: The AD Domain Does Not Exist"	
	EXIT
}

### All Modes - Testing If Required Permissions Are Available (Domain/Enterprise Admin Credentials)
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
Logging "TESTING IF REQUIRED PERMISSIONS ARE AVAILABLE (DOMAIN/ENTERPRISE ADMINS OR ADMINISTRATORS CREDENTIALS)..."
Logging ""

# The AD Forest Is Local, We Can Test For Role Membership Of Either Domain Admins Or Enterprise Admins.
If ($localADforest -eq $true) {
	# Validate The User Account Running This Script Is A Member Of The Domain Admins Group Of The Targeted AD Domain
	$targetedDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}).DomainSID
	$domainAdminRID = "512"
	$domainAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($targetedDomainObjectSID + "-" + $domainAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
	$userIsDomainAdmin = $null
	$userIsDomainAdmin = testAdminRole $domainAdminRole
	If (!$userIsDomainAdmin) {
		# The User Account Running This Script Has Been Validated Not Being A Member Of The Domain Admins Group Of The Targeted AD Domain
		# Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
		$forestRootDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.IsRootDomain -eq "TRUE"}).DomainSID
		$enterpriseAdminRID = "519"
		$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($forestRootDomainObjectSID + "-" + $enterpriseAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
		$userIsEnterpriseAdmin = $null
		$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
		If (!$userIsEnterpriseAdmin) {
			# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
			Logging "The user account '$adRunningUserAccount' IS NOT running with Domain/Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..."
			Logging "The user account '$adRunningUserAccount' IS NOT a member of '$domainAdminRole' and NOT a member of '$enterpriseAdminRole'!..."
			Logging ""
			Logging "For this script to run successfully, Domain/Enterprise Administrator equivalent permissions are required..."
			Logging ""
			Logging "Aborting Script..."
			Logging ""
			Email "Krbtgt Error: Please Check The Credentials Are Domain/Enterprise Administrator Equivalent"
			EXIT
		} Else {
			# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
			Logging "The user account '$adRunningUserAccount' is running with Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..."
			Logging "The user account '$adRunningUserAccount' is a member of '$enterpriseAdminRole'!..."
			Logging ""
			Logging "Continuing Script..."
			Logging ""
		}
	} Else {
		# The User Account Running This Script Has Been Validated To Be A Member Of The Domain Admins Group Of The Targeted AD Domain
		Logging "The user account '$adRunningUserAccount' is running with Domain Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..."
		Logging "The user account '$adRunningUserAccount' is a member of '$domainAdminRole'!..."
		Logging ""
		Logging "Continuing Script..."
		Logging ""
	}
}

### All Modes - Gathering AD Domain Information
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
Logging "GATHERING TARGETED AD DOMAIN INFORMATION..."
Logging ""

# Target AD Domain Data
$targetedADdomainData = $null
$targetedADdomainData = $tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}

# Retrieve The HostName Of Nearest RWDC In The AD Domain
$targetedADdomainNearestRWDC = $null
$targetedADdomainNearestRWDC = $targetedADdomainData.NearestRWDC

# Retrieve Information For The AD Domain That Was Chosen
$thisADDomain = $null
Try {
	If ($localADforest -eq $true) {
		$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDC
	}
} Catch {
	$thisADDomain = $null
}
If ($thisADDomain) {
	# Retrieve The Domain SID
	$targetedADdomainDomainSID = $null
	$targetedADdomainDomainSID = $thisADDomain.DomainSID.Value

	# Retrieve The HostName Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	$targetedADdomainRWDCWithPDCFSMOFQDN = $null
	$targetedADdomainRWDCWithPDCFSMOFQDN = $thisADDomain.PDCEmulator

	# Retrieve The DSA DN Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = $null
	If ($localADforest -eq $true) {
		$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDC).NTDSSettingsObjectDN
	}
	
	# Retrieve Domain Functional Level/Mode Of The AD Domain
	$targetedADdomainDomainFunctionalMode = $null
	$targetedADdomainDomainFunctionalMode = $thisADDomain.DomainMode
	$targetedADdomainDomainFunctionalModeLevel = $null
	If ($localADforest -eq $true) {
		$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDC)."msDS-Behavior-Version"
	}
	
	# Determine The Max Tgt Lifetime In Hours And The Max Clock Skew In Minutes
	Try {
		$gpoObjXML = $null
		If ($localADforest -eq $true) {
			[xml]$gpoObjXML = Get-GPOReport -Domain $targetedADdomainFQDN -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml -Server $targetedADdomainNearestRWDC
		}
		$targetedADdomainMaxTgtLifetimeHrs = $null
		$targetedADdomainMaxTgtLifetimeHrs = (($gpoObjXML.gpo.Computer.ExtensionData | Where-Object{$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object{$_.Name -eq 'MaxTicketAge'}).SettingNumber
		$targetedADdomainMaxClockSkewMins = $null
		$targetedADdomainMaxClockSkewMins = (($gpoObjXML.gpo.Computer.ExtensionData | Where-Object{$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object{$_.Name -eq 'MaxClockSkew'}).SettingNumber
		$sourceInfoFrom = "Default Domain GPO"
	} Catch {
		Logging "Could not lookup 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) from the 'Default Domain Policy' GPO, so default values will be assumed."
		Logging ""
		$targetedADdomainMaxTgtLifetimeHrs = 10
		$targetedADdomainMaxClockSkewMins = 5
		$sourceInfoFrom = "Assumed"
	}
} Else {
	$targetedADdomainRWDCWithPDCFSMOFQDN = "Unavailable"
	$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN = "Unavailable"
	$targetedADdomainDomainFunctionalMode = "Unavailable"
	$targetedADdomainDomainFunctionalModeLevel = "Unavailable"
	$targetedADdomainMaxTgtLifetimeHrs = "Unavailable"
	$targetedADdomainMaxClockSkewMins = "Unavailable"
	$sourceInfoFrom = "Unavailable"
}

# Present The Information
Logging "Domain FQDN...........................: '$targetedADdomainFQDN'"
Logging "Domain Functional Mode................: '$targetedADdomainDomainFunctionalMode'"
Logging "Domain Functional Mode Level..........: '$targetedADdomainDomainFunctionalModeLevel'"
Logging "FQDN RWDC With PDC FSMO...............: '$targetedADdomainRWDCWithPDCFSMOFQDN'"
Logging "DSA RWDC With PDC FSMO................: '$targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN'"
Logging "Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
Logging "Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
Logging "TGT Lifetime/Clock Skew Sourced From..: '$sourceInfoFrom'"
Logging ""
Logging "Checking Domain Functional Mode of targeted AD domain '$targetedADdomainFQDN' is high enough..."

# Check If The Domain Functional Level/Mode Of The AD Domain Is High Enough To Continue
If ($targetedADdomainDomainFunctionalModeLevel -ne "Unavailable" -And $targetedADdomainDomainFunctionalModeLevel -ge 3) {
	# If The Domain Functional Level/Mode Of The AD Domain Is Equal Or Higher Than Windows Server 2008 (3), Then Continue
	Logging ""
	Logging "The specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..."
	Logging ""
	Logging "Continuing Script..."
	Logging ""
} Else {
	# If The Domain Functional Level/Mode Of The AD Domain Is Lower Than Windows Server 2008 (3) Or It Cannot Be Determined, Then Abort
	Logging ""
	Logging "It CANNOT be determined the specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..."
	Logging ""
	Logging "AD domains with Windows Server 2000/2003 DCs CANNOT do KDC PAC validation using the previous (N-1) KrbTgt Account Password"
	Logging "like Windows Server 2008 and higher DCs are able to. Windows Server 2000/2003 DCs will only attempt it with the current (N)"
	Logging "KrbTgt Account Password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed,"
	Logging "authentication issues could be experience because the target server gets a PAC validation error when asking the KDC (DC)"
	Logging "to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server."
	Logging "This problem would potentially persist for the lifetime of the service ticket(s). And by the way... for Windows Server"
	Logging "2000/2003 support already ended years ago. Time to upgrade to higher version dude!"
	Logging "Be aware though, when increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account"
	Logging "will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new"
	Logging "keys for DES, RC4, AES128, AES256!"
	Logging ""
	Logging "Aborting Script..."
	Logging ""
	Email "Krbtgt Error: Domain Functional Level/Mode Of The AD Domain Is Lower Than Windows Server 2008 Or It Cannot Be Determined"
	EXIT
}

### All Modes - Gathering Domain Controller Information And Testing Connectivity
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
Logging "GATHERING DOMAIN CONTROLLER INFORMATION AND TESTING CONNECTIVITY..."
Logging ""

# Define An Empty List/Table That Will Contain All DCs In The AD Domain And Related Information
$tableOfDCsInADDomain = @()

# Retrieve All The RWDCs In The AD Domain
$listOfRWDCsInADDomain = $null
$listOfRWDCsInADDomain = $thisADDomain.ReplicaDirectoryServers

# Set The Counters To Zero
$nrOfRWDCs = 0
$nrOfReachableRWDCs = 0
$nrOfUnReachableRWDCs = 0

# Execute For All RWDCs In The AD Domain If Any
If ($listOfRWDCsInADDomain) {
	$listOfRWDCsInADDomain | ForEach-Object{
		# Get The FQDN Of The RWDC
		$rwdcFQDN = $null
		$rwdcFQDN = $_
		
		# Retrieve The Object Of The RWDC From AD
		$rwdcObj = $null
		If ($localADforest -eq $true) {
			$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDC
		}
		
		# Define The Columns For The RWDCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","Krb Tgt","Pwd Last Set","Org RWDC","Org Time","Ver","IP Address","OS Version",Reachable,"Source RWDC FQDN","Source RWDC DSA"
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Host Name" = $null
		$tableOfDCsInADDomainObj."Host Name" = $rwdcFQDN
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj.PDC = $null
		If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {
			$tableOfDCsInADDomainObj.PDC = $True
		} Else {
			$tableOfDCsInADDomainObj.PDC = $False
		}
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Site Name" = $null
		$tableOfDCsInADDomainObj."Site Name" = $rwdcObj.Site
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."DS Type" = $null
		$tableOfDCsInADDomainObj."DS Type" = "Read/Write"
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$rwdcKrbTgtSamAccountName = $null
		If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 4) {
			# Use The PROD/REAL KrbTgt Account Of The RWDC
			$rwdcKrbTgtSamAccountName = "krbtgt"
		}
		If ($modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
			# Use The TEST/BOGUS KrbTgt Account Of The RWDC
			$rwdcKrbTgtSamAccountName = "krbtgt_TEST"
		}
		$tableOfDCsInADDomainObj."Krb Tgt" = $rwdcKrbTgtSamAccountName
		
		# Retrieve The Object Of The KrbTgt Account
		$rwdcKrbTgtObject = $null
		If ($localADforest -eq $true) {
			$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN
		}
		$tableOfDCsInADDomainObj."Pwd Last Set" = $null
		$tableOfDCsInADDomainObj."Org RWDC" = $null
		$tableOfDCsInADDomainObj."Org Time" = $null
		$tableOfDCsInADDomainObj."Ver" = $null
		If ($rwdcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rwdcKrbTgtObjectDN = $null
			$rwdcKrbTgtObjectDN = $rwdcKrbTgtObject.DistinguishedName
			
			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rwdcKrbTgtPwdLastSet = $null
			$rwdcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rwdcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = $rwdcKrbTgtPwdLastSet
			
			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$metadataObject = $null
			If ($localADforest -eq $true) {
				$metadataObject = Get-ADReplicationAttributeMetadata $rwdcKrbTgtObjectDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN
			}
			$metadataObjectAttribPwdLastSet = $null
			$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
			$orgRWDCNTDSSettingsObjectDN = $null
			$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
			$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
			If ($orgRWDCNTDSSettingsObjectDN) {			
				# Strip "CN=NTDS Settings," To End Up With The Server Object DN
				$orgRWDCServerObjectDN = $null
				$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)
				
				# Connect To The Server Object DN
				$orgRWDCServerObjectObj = $null
				If ($localADforest -eq $true) {
					$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN")
				}
				$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
			} Else {
				$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
			}
			$metadataObjectAttribPwdLastSetOrgTime = $null
			$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$metadataObjectAttribPwdLastSetVersion = $null
			$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Org RWDC" = $metadataObjectAttribPwdLastSetOrgRWDCFQDN
			$tableOfDCsInADDomainObj."Org Time" = $metadataObjectAttribPwdLastSetOrgTime
			$tableOfDCsInADDomainObj."Ver" = $metadataObjectAttribPwdLastSetVersion
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = "No Such Object"
			$tableOfDCsInADDomainObj."Org RWDC" = "No Such Object"
			$tableOfDCsInADDomainObj."Org Time" = "No Such Object"
			$tableOfDCsInADDomainObj."Ver" = "No Such Object"
		}
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."IP Address" = $null
		$tableOfDCsInADDomainObj."IP Address" = $rwdcObj.IPv4Address
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."OS Version" = $null
		$tableOfDCsInADDomainObj."OS Version" = $rwdcObj.OperatingSystem
		
		# Define The Ports To Check Against
		$ports = 135,389	# RPC Endpoint Mapper, LDAP
		
		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true
		
		# For Every Defined Port Check The Connection And Report
		$ports | ForEach-Object{
			# Set The Port To Check Against
			$port = $null
			$port = $_
			
			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck $rwdcFQDN $port 500
			If ($connectionResult -eq "ERROR") {
				$connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RWDC
			$rwdcRootDSEObj = $null
			If ($localADforest -eq $true) {
				$rwdcRootDSEObj = [ADSI]"LDAP://$rwdcFQDN/rootDSE"
			}
			If ($rwdcRootDSEObj.Path -eq $null) {
				# If It Throws An Error Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RWDCs
				$tableOfDCsInADDomainObj.Reachable = $False
				$nrOfUnReachableRWDCs += 1
				
			} Else {
				# If It Does Not Throw An Error Then The RWDC Is Available/Reachable And Increase The Counter Of Reachable RWDCs
				$tableOfDCsInADDomainObj.Reachable = $True
				$nrOfReachableRWDCs += 1
			}
		} Else {
			# If The Connection Check Is Not OK Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RWDCs
			$tableOfDCsInADDomainObj.Reachable = $False
			$nrOfUnReachableRWDCs += 1
		}
		If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {
			# If The RWDC Is The RWDC With The PDC FSMO, Then Do Not Specify A Source RWDC As The RWDC With The PDC FSMO Is The Source Originating RWDC
			$tableOfDCsInADDomainObj."Source RWDC FQDN" = "N.A."
			$tableOfDCsInADDomainObj."Source RWDC DSA" = "N.A."
		} Else {
			# If The RWDC Is Not The RWDC With The PDC FSMO, Then Specify A Source RWDC Being The RWDC With The PDC FSMO As The Source Originating RWDC
			$tableOfDCsInADDomainObj."Source RWDC FQDN" = $targetedADdomainRWDCWithPDCFSMOFQDN
			$tableOfDCsInADDomainObj."Source RWDC DSA" = $targetedADdomainRWDCWithPDCFSMONTDSSettingsObjectDN
		}
		
		# Increase The Counter For The Number Of RWDCs
		$nrOfRWDCs += 1
		
		# Add The Row For The RWDC To The Table
		$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
	}
}
	
# Retrieve All The RODCs In The AD Domain
$listOfRODCsInADDomain = $null
$listOfRODCsInADDomain = $thisADDomain.ReadOnlyReplicaDirectoryServers

# Set The Counters To Zero
$nrOfRODCs = 0
$nrOfReachableRODCs = 0
$nrOfUnReachableRODCs = 0
$nrOfUnDetermined = 0

# Execute For All RODCs In The AD Domain
If ($listOfRODCsInADDomain) {
	$listOfRODCsInADDomain | ForEach-Object{
		# Get The FQDN Of The RODC
		$rodcFQDN = $null
		$rodcFQDN = $_
		
		# Get The FQDN Of The RODC
		$rodcObj = $null
		If ($localADforest -eq $true) {
			$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDC
		}
		# Define The Columns For The RODCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","Krb Tgt","Pwd Last Set","Org RWDC","Org Time","Ver","IP Address","OS Version",Reachable,"Source RWDC FQDN","Source RWDC DSA"
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Host Name" = $null
		$tableOfDCsInADDomainObj."Host Name" = $rodcFQDN
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj.PDC = $null
		$tableOfDCsInADDomainObj.PDC = $False
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Site Name" = $null
		If ($rodcObj.OperatingSystem) {
			$tableOfDCsInADDomainObj."Site Name" = $rodcObj.Site
		} Else {
			$tableOfDCsInADDomainObj."Site Name" = "Unknown"
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."DS Type" = $null
		$tableOfDCsInADDomainObj."DS Type" = "Read-Only"
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$rodcKrbTgtSamAccountName = $null
		If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 4) {
			# Use The PROD/REAL KrbTgt Account Of The RODC
			If ($localADforest -eq $true) {
				$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDC)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDC).Name
			}
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Krb Tgt" = $null
		$tableOfDCsInADDomainObj."Krb Tgt" = $rodcKrbTgtSamAccountName
		
		# Retrieve The Object Of The KrbTgt Account
		$rodcKrbTgtObject = $null
		If ($localADforest -eq $true) {
			$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN
		}
		$tableOfDCsInADDomainObj."Pwd Last Set" = $null
		$tableOfDCsInADDomainObj."Org RWDC" = $null
		$tableOfDCsInADDomainObj."Org Time" = $null
		$tableOfDCsInADDomainObj."Ver" = $null
		If ($rodcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rodcKrbTgtObjectDN = $null
			$rodcKrbTgtObjectDN = $rodcKrbTgtObject.DistinguishedName		
			
			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rodcKrbTgtPwdLastSet = $null
			$rodcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rodcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = $rodcKrbTgtPwdLastSet
			
			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$metadataObject = $null
			If ($localADforest -eq $true) {
				$metadataObject = Get-ADReplicationAttributeMetadata $rodcKrbTgtObjectDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN
			}
			$metadataObjectAttribPwdLastSet = $null
			$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
			$orgRWDCNTDSSettingsObjectDN = $null
			$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
			$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
			If ($orgRWDCNTDSSettingsObjectDN) {			
				# Strip "CN=NTDS Settings," To End Up With The Server Object DN
				$orgRWDCServerObjectDN = $null
				$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)
				
				# Connect To The Server Object DN
				$orgRWDCServerObjectObj = $null
				If ($localADforest -eq $true) {
					$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN")
				}
				$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
			} Else {
				$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
			}
			$metadataObjectAttribPwdLastSetOrgTime = $null
			$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$metadataObjectAttribPwdLastSetVersion = $null
			$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version
			
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Org RWDC" = $metadataObjectAttribPwdLastSetOrgRWDCFQDN
			$tableOfDCsInADDomainObj."Org Time" = $metadataObjectAttribPwdLastSetOrgTime
			$tableOfDCsInADDomainObj."Ver" = $metadataObjectAttribPwdLastSetVersion
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = "No Such Object"
			$tableOfDCsInADDomainObj."Org RWDC" = "No Such Object"
			$tableOfDCsInADDomainObj."Org Time" = "No Such Object"
			$tableOfDCsInADDomainObj."Ver" = "No Such Object"
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."IP Address" = $null
		If ($rodcObj.OperatingSystem) {
			$tableOfDCsInADDomainObj."IP Address" = $rodcObj.IPv4Address
		} Else {
			$tableOfDCsInADDomainObj."IP Address" = "Unknown"
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."OS Version" = $null
		If ($rodcObj.OperatingSystem) {
			$tableOfDCsInADDomainObj."OS Version" = $rodcObj.OperatingSystem
		} Else {
			$tableOfDCsInADDomainObj."OS Version" = "Unknown"
		}
		
		# Define The Ports To Check Against
		$ports = 135,389	# RPC Endpoint Mapper, LDAP
		
		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true
		
		# For Every Defined Port Check The Connection And Report
		$ports | ForEach-Object{
			# Set The Port To Check Against
			$port = $null
			$port = $_
			
			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck $rodcFQDN $port 500
			If ($connectionResult -eq "ERROR") {
				$connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {		
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RODC
			$rodcRootDSEObj = $null
			If ($localADforest -eq $true) {
				$rodcRootDSEObj = [ADSI]"LDAP://$rodcFQDN/rootDSE"
			}
			If ($rodcRootDSEObj.Path -eq $null) {
				# If It Throws An Error Then The RODC Is Not Available/Reachable And Increase The Counter Of Unreachable RODCs
				$tableOfDCsInADDomainObj.Reachable = $False
				$nrOfUnReachableRODCs += 1
			} Else {
				# If It Does Not Throw An Error Then The RWDC Is Available/Reachable And Increase The Counter Of Reachable RODCs
				$tableOfDCsInADDomainObj.Reachable = $True
				$nrOfReachableRODCs += 1
			}
		} Else {
			# If The Connection Check Is Not OK Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RODCs
			$tableOfDCsInADDomainObj.Reachable = $False
			$nrOfUnReachableRODCs += 1
		}
		If ($rodcObj.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC
			If ($tableOfDCsInADDomainObj.Reachable -eq $True) {
				# If The RODC Is Available/Reachable
				# Get The DSA DN Of The RODC
				$rodcNTDSSettingsObjectDN = $null
				$rodcNTDSSettingsObjectDN = $rodcObj.NTDSSettingsObjectDN
				
				# Define An LDAP Query With A Search Base And A Filter To Determine The DSA DN Of The Source RWDC Of The RODC
				$dsDirSearcher = $null
				$dsDirSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
				$dsDirSearcher.SearchRoot = $null
				If ($localADforest -eq $true) {
					$dsDirSearcher.SearchRoot = "LDAP://$rodcFQDN/$rodcNTDSSettingsObjectDN"
				}
				$dsDirSearcher.Filter = $null
				$dsDirSearcher.Filter = "(&(objectClass=nTDSConnection)(ms-DS-ReplicatesNCReason=*))"
				$sourceRWDCsNTDSSettingsObjectDN = $null
				$sourceRWDCsNTDSSettingsObjectDN = $dsDirSearcher.FindAll().Properties.fromserver
				
				# For Every DSA DN Of The Source RWDC Retrieved
				$sourceRWDCsNTDSSettingsObjectDN | ForEach-Object{
					$sourceRWDCNTDSSettingsObjectDN = $null
					$sourceRWDCNTDSSettingsObjectDN = $_
					
					# Strip "CN=NTDS Settings," To End Up With The Server Object DN
					$sourceRWDCServerObjectDN = $null
					$sourceRWDCServerObjectDN = $sourceRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)
					
					# Connect To The Server Object DN
					If ($localADforest -eq $true) {
						$sourceRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainNearestRWDC/$sourceRWDCServerObjectDN")
					}
					# If The Domain Of The Source RWDC Matches The Domain Of The RODC, Then That's The One We Need
					If (($sourceRWDCServerObjectObj.dnshostname).SubString($sourceRWDCServerObjectObj.name.Length + 1) -eq $rodcObj.Domain) {
						# The HostName Of Source RWDC Used By The RODC - Set The Corresponding Value Of The RODC In The Correct Column Of The Table
						$tableOfDCsInADDomainObj."Source RWDC FQDN" = $sourceRWDCServerObjectObj.dnshostname[0]
						
						# The DSA DN Of Source RWDC Used By The RODC - Set The Corresponding Value Of The RODC In The Correct Column Of The Table
						$tableOfDCsInADDomainObj."Source RWDC DSA" = $sourceRWDCsNTDSSettingsObjectDN[0]
					}
				}
			} Else {
				# If The RODC Is Available/Reachable
				# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
				$tableOfDCsInADDomainObj."Source RWDC FQDN" = "RODC Unreachable"
				$tableOfDCsInADDomainObj."Source RWDC DSA" = "RODC Unreachable"
			}
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Source RWDC FQDN" = "Unknown"
			$tableOfDCsInADDomainObj."Source RWDC DSA" = "Unknown"
		}
		If ($rodcObj.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC, Therefore Increase The Counter For Real RODCs
			$nrOfRODCs += 1
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC, Therefore Increase The Counter For Unknown RODCs
			$nrOfUnDetermined += 1
		}
		# Add The Row For The RODC To The Table
		$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
	}
}

# Sort The Table With DCs In The AD Domain In The Order "DS Type" (Read/Write At The Top), Then If It Is The PDC Or Not (PDC At The Top), Then If It Is Reachable Or Not (Reachable At the Top)
$tableOfDCsInADDomain = $tableOfDCsInADDomain | Sort-Object -Property @{Expression = "DS Type"; Descending = $False}, @{Expression = "PDC"; Descending = $True}, @{Expression = "Reachable"; Descending = $True}

# Determine The Number Of DCs Based Upon The Number Of RWDCs And The Number Of RODCs
$nrOfDCs = $nrOfRWDCs + $nrOfRODCs

# Display The Information
Logging ""
Logging "List Of Domain Controllers In AD Domains '$targetedADdomainFQDN'..."
Logging ""
Logging "$($tableOfDCsInADDomain | Out-String)"
Logging ""
Logging "REMARKS:"
Logging " - 'N.A.' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RWDC is considered as the master for this script."
Logging " - 'RODC Unreachable' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RODC cannot be reached to determine its replicating source"
Logging "     RWDC/DSA. The unavailability can be due to firewalls/networking or the RODC actually being down."
Logging " - 'Unknown' in various columns means that an RODC was found that may not be a true Windows Server RODC. It may be an appliance acting as an RODC."
Logging " - 'RWDC Demoted' in the column 'Org RWDC' means the RWDC existed once, but it does not exist anymore as it has been decommissioned in the past."
Logging "     This is normal."
Logging " - 'No Such Object' in the columns 'Pwd Last Set', 'Org RWDC', 'Org Time' or 'Ver' means the targeted object was not found in the AD domain."
Logging "     Although this is possible for any targeted object, this is most likely the case when targeting the KrbTgt TEST/BOGUS accounts and if those"
Logging "     do not exist yet. This may also occur for an appliance acting as an RODC as in that case no KrbTgt TEST/BOGUS account is created."
Logging ""
Logging "  --> Found [$nrOfDCs] Real DC(s) In AD Domain..."
Logging "  --> Found [$nrOfRWDCs] RWDC(s) In AD Domain..."
Logging "  --> Found [$nrOfReachableRWDCs] Reachable RWDC(s) In AD Domain..."
Logging "  --> Found [$nrOfUnReachableRWDCs] UnReachable RWDC(s) In AD Domain..."
Logging "  --> Found [$nrOfRODCs] RODC(s) In AD Domain..."
Logging "  --> Found [$nrOfReachableRODCs] Reachable RODC(s) In AD Domain..."
Logging "  --> Found [$nrOfUnReachableRODCs] UnReachable RODC(s) In AD Domain..."
Logging "  --> Found [$nrOfUnDetermined] Undetermined RODC(s) In AD Domain..."
Logging ""

### Mode 4 - Selecting The KrbTgt Account To Target And Scope If Applicable (Only Applicable To RODCs)
If ($modeOfOperationNr -eq 4) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
	Logging "THE SCOPE OF THE KRBTGT ACCOUNT(S) TO TARGET..."
	Logging ""
	Logging " - 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain"
	Logging ""
	
	# If KrbTgt Account Scope 1
	If ($targetKrbTgtAccountNr -eq 1) {
		$targetKrbTgtAccountDescription = "1 - Scope of KrbTgt in use by all RWDCs in the AD Domain..."
	}
    Else {
		Logging "  -->  Scope KrbTgt Account Target: ERROR - Exit Script..."
		Logging ""
		Email "Krbtgt Error: The Scope Of The Krbtgt Reset Has Been Changed"
		EXIT
	}
}

### Mode 4 - Real Reset Mode
If ($modeOfOperationNr -eq 4) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------"
	Logging "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED KRBTGT ACCOUNT(S) ($targetKrbTgtAccountDescription)"
	Logging ""
		
	# KrbTgt in use by all RWDCs in the AD Domain
	If ($targetKrbTgtAccountNr -eq 1) {
		# Retrieve The KrbTgt Account Listed For The RWDC With The PDC FSMO
		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
		
		# Retrieve The Hosted Listed For The RWDC With The PDC FSMO
		$targetedADdomainSourceRWDCFQDN = $null
		$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
		
		# Retrieve The DN Of The KrbTgt Account
		$krbTgtDN = $null
		If ($localADforest -eq $true) {
			$krbTgtDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDC).DistinguishedName
		}
		Logging "+++++"
		Logging "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtDN' +++"
		Logging "+++ Used By RWDC.................: 'All RWDCs' +++"
		Logging "+++++"
		Logging ""

		# Retrieve The Status Of Hosting The PDC FSMO From The RWDC Hosting The PDC FSMO (Duh!)
		$targetedADdomainSourceRWDCIsPDC = $null
		$targetedADdomainSourceRWDCIsPDC = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True}).PDC
		
		# Retrieve The SiteName Listed For The RWDC With The PDC FSMO
		$targetedADdomainSourceRWDCSiteName = $null
		$targetedADdomainSourceRWDCSiteName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Site Name"
		
		# Retrieve The DS Type Listed For The RWDC With The PDC FSMO
		$targetedADdomainSourceRWDCDSType = $null
		$targetedADdomainSourceRWDCDSType = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."DS Type"
		
		# Retrieve The IP Address Listed For The RWDC With The PDC FSMO
		$targetedADdomainSourceRWDCIPAddress = $null
		$targetedADdomainSourceRWDCIPAddress = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."IP Address"
		
		# Retrieve The Reachability Listed For The RWDC With The PDC FSMO
		$targetedADdomainRWDCReachability = $null
		$targetedADdomainRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True}).Reachable
		
		# Retrieve The FQDN Of The Source RWDC Listed For The RWDC With The PDC FSMO
		$targetedADdomainRWDCSourceRWDCFQDN = "N.A."
		
		# Set The Start Time For The RWDC With The PDC FSMO
		$targetedADdomainRWDCTime = 0.00

		If ($targetedADdomainRWDCReachability) {
			# If The RWDC With The PDC FSMO Is Reachable
			# If Mode 3 Or 4
			If ($modeOfOperationNr -eq 4) {
				# Retrieve The KrbTgt Account Object
				$targetObjectToCheck = $null
				If ($localADforest -eq $true) {
					$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCWithPDCFSMOFQDN
				}
				If ($targetObjectToCheck) {
					# If The KrbTgt Account Object Exists (You're In Deep Sh!t If The Account Does Not Exist! :-))
					# Retrieve The DN Of The KrbTgt Account Object
					$targetObjectToCheckDN = $null
					$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName			
					
					# Retrieve The Password Last Set Of The KrbTgt Account Object
					$targetObjectToCheckPwdLastSet = $null
					$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))
					
					# Calculate The Expiration Date/Time Of N-1 Kerberos Tickets
					$expirationTimeForNMinusOneKerbTickets = $null
					$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($targetedADdomainMaxTgtLifetimeHrs)).AddMinutes($targetedADdomainMaxClockSkewMins)).AddMinutes($targetedADdomainMaxClockSkewMins)

					# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
					$metadataObject = $null
					If ($localADforest -eq $true) {
						$metadataObject = Get-ADReplicationAttributeMetadata $targetObjectToCheckDN -Server $targetedADdomainRWDCWithPDCFSMOFQDN
					}
					$metadataObjectAttribPwdLastSet = $null
					$metadataObjectAttribPwdLastSet = $metadataObject | Where-Object{$_.AttributeName -eq "pwdLastSet"}
					$orgRWDCNTDSSettingsObjectDN = $null
					$orgRWDCNTDSSettingsObjectDN = $metadataObjectAttribPwdLastSet.LastOriginatingChangeDirectoryServerIdentity
					$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $null
					If ($orgRWDCNTDSSettingsObjectDN) {			
						# Strip "CN=NTDS Settings," To End Up With The Server Object DN
						$orgRWDCServerObjectDN = $null
						$orgRWDCServerObjectDN = $orgRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)
						
						# Connect To The Server Object DN
						$orgRWDCServerObjectObj = $null
						If ($localADforest -eq $true) {
							$orgRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainRWDCWithPDCFSMOFQDN/$orgRWDCServerObjectDN")
						}
						$metadataObjectAttribPwdLastSetOrgRWDCFQDN = $orgRWDCServerObjectObj.dnshostname[0]
					} Else {
						$metadataObjectAttribPwdLastSetOrgRWDCFQDN = "RWDC Demoted"
					}
					$metadataObjectAttribPwdLastSetOrgTime = $null
					$metadataObjectAttribPwdLastSetOrgTime = Get-Date $($metadataObjectAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
					$metadataObjectAttribPwdLastSetVersion = $null
					$metadataObjectAttribPwdLastSetVersion = $metadataObjectAttribPwdLastSet.Version

					$okToReset = $null
					If ($expirationTimeForNMinusOneKerbTickets -lt [DateTime]::Now) {
						# Allow The Password Reset To Occur Without Questions If The Expiration Date/Time Of N-1 Kerberos Tickets Is Earlier Than The Current Time
						$okToReset = $True
					} Else {
						# Stop the password reset process
                        $okToReset = $False
                        Logging "  --> According To RWDC.....................: '$targetedADdomainSourceRWDCFQDN'"
						Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
						Logging "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
						Logging "  --> Date/Time Now.........................: '$(Get-Date $([DateTime]::Now) -f 'yyyy-MM-dd HH:mm:ss')'"
						Logging "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
						Logging "  --> Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
						Logging "  --> Originating RWDC Previous Change......: '$metadataObjectAttribPwdLastSetOrgRWDCFQDN'"
						Logging "  --> Originating Time Previous Change......: '$metadataObjectAttribPwdLastSetOrgTime'"
						Logging "  --> Current Version Of Attribute Value....: '$metadataObjectAttribPwdLastSetVersion'"
						Logging ""
						Logging "  --> Not Resetting KrbTgt Account Password as last set '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')' is less than the maximum TGT lifetime ago."
						Logging ""
                        Email "Krbtgt Error: Not Resetting KrbTgt Account Password as last change was less than the maximum TGT lifetime ago."
                        EXIT
                        
					}
                    If ($okToReset) {
						# If OK To Reset Then Execute The Password Reset Of The KrbTgt Account
						setPasswordOfADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $remoteCredsUsed $adminCreds
					}
				} Else {
					# If The KrbTgt Account Object Does Not Exist (You're In Deep Sh!t If The Account Does Not Exist! :-))
					Logging "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..."
					Logging ""
				}
			}
		} Else {
			# If The RWDC With The PDC FSMO Is NOT Reachable
		
			Logging ""
			Logging "The RWDC '$targetedADdomainSourceRWDCFQDN' to make the change on is not reachable/available..."
			Logging ""
		}
		
		# If The DN Of The Target Object To Check Was Determined/Found
		If ($targetObjectToCheckDN) {
			# Retrieve/Define The Starting List With RWDCs
			$listOfDCsToCheckObjectOnStart = $null
			$listOfDCsToCheckObjectOnStart = ($tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read/Write"})
			
			# Define An Empty List/Table For At The End That Will Contain All DCs In The AD Domain And Related Information
			$listOfDCsToCheckObjectOnEnd = @()
			
			# Define The Columns For The RWDCs In The AD Domain To Be Filled In
			$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
			$listOfDCsToCheckObjectOnEndObj."Host Name" = $targetedADdomainSourceRWDCFQDN
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj.PDC = $null
			$listOfDCsToCheckObjectOnEndObj.PDC = $targetedADdomainSourceRWDCIsPDC
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
			$listOfDCsToCheckObjectOnEndObj."Site Name" = $targetedADdomainSourceRWDCSiteName
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
			$listOfDCsToCheckObjectOnEndObj."DS Type" = $targetedADdomainSourceRWDCDSType
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
			$listOfDCsToCheckObjectOnEndObj."IP Address" = $targetedADdomainSourceRWDCIPAddress
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj.Reachable = $null
			$listOfDCsToCheckObjectOnEndObj.Reachable = $targetedADdomainRWDCReachability
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
			$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainRWDCSourceRWDCFQDN
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$listOfDCsToCheckObjectOnEndObj.Time = $null
			$listOfDCsToCheckObjectOnEndObj.Time = $targetedADdomainRWDCTime
			
			# Add The Row For The RWDC To The Table
			$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj

			# Execute The Check AD Replication Convergence Function For The Targeted Object To Check
			checkADReplicationConvergence $targetedADdomainFQDN $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnEnd $modeOfOperationNr $localADforest $remoteCredsUsed $adminCreds
		}
        Email "Krbtgt Reset: Scheduled Password Reset Completed Successfully"
	}
}