Function Get-SessionInfo {
    
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [ValidateLength(1,16)]
        [ValidatePattern("[A-Za-z0-9-]")]
        [String]$user,

        [Parameter(Mandatory=$False)]
        [String]$LogPath,

        [Parameter(Mandatory=$False)]
        [String]$AdminAddress
    )
    
    $logPath = "C:\temp\SessionInfo"
    $domain = (Get-ADDomain).name
    
    #Write-host "Please type user ID without domain info"
    #$user = Read-Host
    IF($AdminAddress){
        $XASessions = Get-BrokerSession -AdminAddress $AdminAddress -UserName 
    }
    Else{
    $XASessions = Get-BrokerSession -UserName "$domain\$user"
    }
    $sessionInfo = @()
    
    #need to add detection for Quser returning a non active state since CTXSession only reports on live sessions
    ForEach($Session in $XASessions){
        $sid = $Session.userSid
        $SessionKey = $Session.SessionKey
        $sessionHolder = Invoke-Command -ComputerName $Session.DNSName -ArgumentList $user,$Sid,$SessionKey -ScriptBlock { 
        
            param($user,$sid,$sessionKey)

            $quser = Quser $user
            #parseUser was imported from some idiot on the internet, should probably rewrite it since it's pretty terrible but I'm lazy AF
                $parseUser = [PSCustomObject]@{
                    Username        = $quser[1].SubString(1, 20).Trim()
                    SessionName     = $quser[1].SubString(23, 17).Trim()
                    ID             = $quser[1].SubString(41, 3).Trim()
                    State           = $quser[1].SubString(46, 6).Trim()
                    Idle           = $quser[1].SubString(54, 9).Trim().Replace('+', '.')
                    LogonTime      = [datetime]$quser[1].SubString(65)
                }
        
            $ctxSession = CTXSession -s $ParseUser.ID /v
            #Parsing out of CTXSession data
            ############################
        
            $Protocols = $ctxSession[2].Split(":")[1].trim()
            $localAddress = $ctxSession[3].Split(":")[1].trim()+":"+$ctxSession[3].Split(":")[2].trim()
            $remoteAddress = $ctxSession[4].Split(":")[1].trim()+":"+$ctxSession[4].Split(":")[2].trim()
            $clientAddress = $ctxSession[5].Split(":")[1].trim()+":"+$ctxSession[5].Split(":")[2].trim()

            IF($Protocols -match "UDP ->"){

                
                
                <#
                
                Session Id 25:
                Transport Protocols:	UDP -> CGP -> ICA
                      Local Address: 	10.12.42.18:2598
                     Remote Address: 	172.16.111.153:60848
                     Client Address: 	172.16.111.153:60848
                
                EDT Reliable Statistics:
                    Bandwidth 11.566 Mbps,  Send Rate 0 bps,  Recv Rate 0 bps,  RTT 77.051 ms
                    Sent             0,  Sent Lost        0 (0.00%),  Rcvd             0,  Rcvd Lost        0 (0.00%)
                    Sent ACKs        0,  Sent NAKs        0,          Rcvd ACKs        0,  Rcvd NAKs        0
                    Flow Window  16383,  Congest Window     16,   Delivery Rate      1
                    EDT MTU: 1500
                
                ICA Statistics:
                     SentBandwidth (bps) =          0    RecvBandwidth (bps) =          0
                     SentPreCompression  =     139906    RecvPreExpansion    =      13360
                     SentPostCompression =      83579    RecvPostExpansion   =      68863
                     Compression Ratio % =         59    Expansion Ratio %   =         19
                     LastLatency         =          0    AverageLatency      =          0
                     IcaBufferLength     =       1306
                
                
                #>
                #Breaks up each line by comma then the trailing character of the section targeted. AKA "Send Rate" is split by the last "e".
                #comments at end of line are the expected output from example above
                #EDT stats
                #line 8
                $bandwidth = ($ctxSession[8].Split(",")[0]).split("h")[1].trim() #11.566 Mbps
                $sendRate = ($ctxSession[8].Split(",")[1]).split("e")[2].trim() #0 bps
                $receiveRate = ($ctxSession[8].Split(",")[2]).split("e")[2].trim() #0 bps
                $rtt = ($ctxSession[8].Split(",")[3]).split("T")[2].trim() #71.314 ms
                #line 9
                $sent = ($ctxSession[9].Split(",")[0]).split("t")[1].trim() #0
                $sentLost = ($ctxSession[9].Split(",")[1]).split("t")[2].trim() # 0 (0.00%) 
                $received = ($ctxSession[9].Split(",")[2]).split("d")[1].trim() # 0
                $receivedLost = ($ctxSession[9].Split(",")[3]).split("t")[1].trim() # 0 (0.00%)
                #line 10 
                $sentACKs = ($ctxSession[10].Split(",")[0]).split("s")[1].trim() #0
                $sentNAKS = ($ctxSession[10].Split(",")[1]).split("s")[1].trim() #0
                $receivedACKs = ($ctxSession[10].Split(",")[2]).split("s")[1].trim() #0
                $receivedNAKS = ($ctxSession[10].Split(",")[3]).split("s")[1].trim() #0
                #line 11
                $flowWindow = ($ctxSession[11].Split(",")[0]).split("w")[2].trim() #16383
                $congestWindow = ($ctxSession[11].Split(",")[1]).split("w")[1].trim() #16 
                $deliveryRate = ($ctxSession[11].Split(",")[2]).split("e")[3].trim() #1
                #line 12
                $MTU = $ctxSession[12].Split(":")[1].trim() #1500
                $edt = [pscustomobject] @{
                    Bandwidth = $bandwidth
                    Sent = [int]$sent
                    SentLost = $sentLost
                    Received = [int]$received
                    ReceivedLost = $receivedLost
                    SentACKs = [int]$sentACKs
                    SentNAKs = [int]$sentNAKS
                    ReceivedACKs = [int]$receivedACKs
                    ReceivedNAKs = [int]$receivedNAKS
                    FlowWindow = [int]$flowWindow
                    CongestWindow = [int]$congestWindow
                    DeliveryRate = [int]$deliveryRate        
                }
        
                #ICA Stats
                #line 15
                $sentBandwidth = $ctxSession[15].Split("=")[1].split("R")[0].trim() #0
                $receivedBandwidth = $ctxSession[15].Split("=")[2].trim() #0
                #line 16
                $sentPreCompression = $ctxSession[16].Split("=")[1].split("R")[0].trim() #139906
                $receivedPreExpansion = $ctxSession[16].Split("=")[2].trim() #13360
                #line 17
                $sentPostCompression = $ctxSession[17].Split("=")[1].split("R")[0].trim() #83579
                $receivedPostExpansion = $ctxSession[17].Split("=")[2].trim() #68863
                #line 18
                $compressionRatio = $ctxSession[18].Split("=")[1].split("E")[0].trim() #59
                $expansionRatio = $ctxSession[18].Split("=")[2].trim() #19
                #line 19
                $lastLatency = $ctxSession[19].Split("=")[1].split("A")[0].trim() #0
                $averageLatency = $ctxSession[19].Split("=")[2].trim() #0
                #line 20
                $icaBufferLength = $ctxSession[20].Split("=")[1].trim() #1306
                $ICA = [pscustomobject] @{
                    SentBandwidth = [int]$sentBandwidth
                    ReceivedBandwidth = [int]$receivedBandwidth
                    SentPreCompression = [int]$sentPreCompression
                    ReceivedPreExpansion = [int]$receivedPreExpansion
                    SentPostCompression = [int]$sentPostCompression
                    RecivedPostExpansion = [int]$receivedPostExpansion
                    CompressionRatio = [int]$compressionRatio
                    ExpansionRatios = [int]$expansionRatio
                    ICABufferLength = [int]$icaBufferLength
                }
            }
            Else{
                $EDT = "NA"
                                #ICA Stats
                #line 8
                $sentBandwidth = $ctxSession[8].Split("=")[1].split("R")[0].trim() #0
                $receivedBandwidth = $ctxSession[8].Split("=")[2].trim() #0
                #line 9
                $sentPreCompression = $ctxSession[9].Split("=")[1].split("R")[0].trim() #139906
                $receivedPreExpansion = $ctxSession[9].Split("=")[2].trim() #13360
                #line 10
                $sentPostCompression = $ctxSession[10].Split("=")[1].split("R")[0].trim() #83579
                $receivedPostExpansion = $ctxSession[10].Split("=")[2].trim() #68863
                #line 11
                $compressionRatio = $ctxSession[11].Split("=")[1].split("E")[0].trim() #59
                $expansionRatio = $ctxSession[11].Split("=")[2].trim() #19
                #line 12
                $lastLatency = $ctxSession[12].Split("=")[1].split("A")[0].trim() #0
                $averageLatency = $ctxSession[12].Split("=")[2].trim() #0
                #line 23
                $icaBufferLength = $ctxSession[13].Split("=")[1].trim() #1306
                $ICA = [pscustomobject] @{
                    SentBandwidth = [int]$sentBandwidth
                    ReceivedBandwidth = [int]$receivedBandwidth
                    SentPreCompression = [int]$sentPreCompression
                    ReceivedPreExpansion = [int]$receivedPreExpansion
                    SentPostCompression = [int]$sentPostCompression
                    RecivedPostExpansion = [int]$receivedPostExpansion
                    CompressionRatio = [int]$compressionRatio
                    ExpansionRatios = [int]$expansionRatio
                    ICABufferLength = [int]$icaBufferLength
                }

            }
            ###########################
            #Session Registry
            $id = $parseUser.id
            $regInfo = Get-ItemProperty -Path HKLM:\Software\Citrix\Ica\Session\$id\Connection
            ###########################
            #FSlogix Registry
            IF(Test-Path HKLM:\SOFTWARE\FSLogix\Profiles\Sessions\$sid){
                $FSLogixReg = Get-ItemProperty -Path HKLM:\SOFTWARE\FSLogix\Profiles\Sessions\$sid 
                IF($fslogixReg.ProfileType -eq 1){$VHDType = "RW"} ELSEIF($fslogixReg.ProfileType -eq 2){$VHDType = "RO"} ELSE{$VHDType = $fslogixReg.ProfileType}
                $FSlogixLocalCache = Test-Path $FSLogixReg.VHDRODiffDiskFilePath
            }

            ###########################
            #Citrix Profile Management Data
            IF(Get-WmiObject -List | ? {$_.name -match "CitrixUserProfileManager"}){
                $CPMSession = Get-WmiObject -Namespace "root\citrix\profiles\metrics" -Class Session | ? {$_.SessionID -match $sessionKey} 
                $CPMDiag = Get-WmiObject -Namespace "root\citrix\profiles\metrics" -Class Diagnostics | ? {$_.SessionID -match $sessionKey} 
                #not currently tracking logon times
                #$CPMLogoff = Get-WmiObject -Namespace "root\citrix\profiles\metrics" -Class LogoffTimings | ? {$_.SessionID -match $sessionKey}
                #$CPMLogon = Get-WmiObject -Namespace "root\citrix\profiles\metrics" -Class LogonTimings | ? {$_.SessionID -match $sessionKey}
            }
            $masterReturn = [pscustomobject]@{
                SessionAddress = $localAddress
                SessionName = $parseUser.SessionName
                SessionID = $parseUser.ID
                SessionState = $parseUser.State
                SessionIdle = $parseUser.Idle
                SessionLogOn = $parseUser.LogonTime
                CPMPath = $CPMDiag.SmbPath
                CPMSize = ($CPMSession.ProfileSize)/1MB
                CPMFileCount = $CPMSession.ProfileFileCount
                CPMFolderCount = $CPMSession.ProfileFolderCount
                CPMProfileType = $CPMSession.ProfileType
                FSLogixType = $VHDType
                FSLogixRoot = $FSLogixReg.VHDRootFilePath
                FSLogixMount = $FSLogixReg.VHDOpenedFilePath
                FSLogixLocalCache = $FSlogixLocalCache
                Protocols = $Protocols
                RemoteAddress = $remoteAddress
                ClientAddress = $clientAddress
                LocalAddress = $localAddress
                MTU = [int]$MTU
                Latency = [int]$lastLatency
                AvgLatency = [int]$averageLatency
                Processes = Get-Process -IncludeUserName | ? {$_.SI -eq [int]$parseUser.ID}
                RegInfo = $regInfo
                EDT = $edt
                ICA = $ICA
                #Troubleshooting
                #Arg0 = $user
                #Arg1 = $sid
                #Arg2 = $sessionKey
            }
            return $masterReturn
        }
        $sessionInfoBuilder = [pscustomobject]@{
            AgentVersion = $Session.AgentVersion
            AppState = $Session.AppState
            AppStateLasteChangeTime = $session.AppStateLastChangeTime
            ApplicationsInUse = $session.ApplicationsInUse
            BrokeringTime = $session.BrokeringTime
            ClientName = $Session.ClientName
            ClientAddress = $sessionHolder.ClientAddress
            ClientPlatform = $session.ClientPlatform
            ClientVersion = $session.ClientVersion
            ConnectionMode = $session.ConnectionMode
            DesktopGroupName = $Session.DesktopGroupName
            DesktopKind = $session.DesktopKind
            OSType = $session.OSType
            HostingServerName = $session.HostingServerName
            HypervisorConnectionName = $session.HypervisorConnectionName
            CitrixIdleDuration = $session.IdleDuration
            ServerIdleDuration = $sessionHolder.SessionIdle
            LaunchedViaIp = $session.LaunchedViaIP
            RemoteAddress = $sessionHolder.RemoteAddress
            LocalAddress = $sessionHolder.LocalAddress
            LaunchedViaPublishedName = $session.LaunchedViaPublishedName
            LogoffInProgress = $session.LogoffInProgress
            LogonInProgress = $session.LogonInProgress
            PersistUserChanges = $session.PersistUserChanges
            Protocol = $session.Protocol
            VDAReportedProtocols = $sessionHolder.Protocols
            SecureICAActive = $session.SecureIcaActive
            VDASessionID = $sessionHolder.SessionId
            Hres = $sessionHolder.RegInfo.Hres
            Vres = $sessionHolder.RegInfo.Vres
            ColorDepth = $sessionHolder.RegInfo.ColorDepth
            CPMPath = $sessionHolder.CPMPath
            CPMSizeMB = $sessionHolder.CPMSize
            CPMFileCount = $sessionHolder.CPMFileCount
            CPMFolderCount = $sessionHolder.CPMFolderCount
            CPMProfileType = $sessionHolder.CPMProfileType
            FSLogixType = $sessionHolder.FSLogixType
            FSLogixRoot = $sessionHolder.FSLogixRoot
            FSLogixMount = $sessionHolder.FSLogixMount
            FSLogixLocalCache = $sessionHolder.FSLogixLocalCache
            SessionKey = $session.SessionKey
            SessionUser = $session.UserName
            SessionState = $session.SessionState
            VDASessionState = $sessionHolder.SessionState
            SessionStateChangeTime = $session.SessionStateChangeTime
            SessionSupport = $session.SessionSupport
            SessionType = $session.SessionType
            VDASessionStartTime = $sessionHolder.SessionLogOn
            SessionLatency = $sessionHolder.Latency
            SessionAvgLatency = $sessionHolder.AvgLatency
            StartTime = $session.StartTime
            ServerName = $sessionHolder.PSComputerName
            MTU = $sessionHolder.MTU
            Processes = $sessionHolder.Processes
            EDT = $sessionHolder.EDT
            ICA = $sessionHolder.ICA
        }
    $sessionInfo += $sessionInfoBuilder

}
#$timeStamp = Get-Date
if($LogPath -ne $null){
    $sessionInfo | Export-Clixml -Path "$logPath\$user.xml" -Force
}
Return $sessionInfo
}
