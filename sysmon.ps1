# SYSMON PowerShel examples

#region ProcessCreate: Event 1
Start-Process PowerShell
$filter = '
<QueryList>
    <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
        <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=1)]]</Select>
    </Query>
</QueryList>'

Get-WinEvent -FilterXml $filter -MaxEvents 1 -ErrorAction SilentlyContinue

# Extra PowerShell goodness to grab the hashes and see what Virus total has to say
$filter = '
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=1)]]</Select>
  </Query>
</QueryList>'

# Extra PowerShell goodness to grab the hashes
$events = Get-WinEvent -FilterXml $filter -ErrorAction SilentlyContinue -MaxEvents 4
$obj = $hashes = @()
foreach ($event in $events) {
    # Converting our data to XML
    $eventXML = [xml]$event.ToXml()
    # Grabbing just the hash
    $resource = ($eventXML.Event.EventData.Data[15].'#text' -split "=")[-1]
    # Creating a list of unique hashes.  This takes the list from 2420 to 181 to test.
    if ($hashes -notcontains $resource) {
        $hashes += $resource
    }
}
# Send the hashes to Virus Total
# 4 per minute limit, may need to put a sleep command in
foreach ($hash in $hashes) {
    $url = 'https://www.virustotal.com/vtapi/v2/file/report'
    $apikey = 'cd32bbf8b8bf486cca07196c430a19aa9e10b797f673d816f7c7618aba8ff952'
    $rest = Invoke-RestMethod -Method Post -Uri $url -Body @{resource = $hash; apikey = $apikey } |
        Select-Object Resource, scan_date, Positives, Total

    if ($rest) { $obj += $rest }
    Start-Sleep -Seconds 16
}

$obj | Out-GridView -Title "Virus Total Data"
#endregion

#region FileCreateTime: Event 2
New-Item -Path C:\TEMP -Name test.log -ItemType File -Force
(Get-Item C:\temp\test.log).CreationTime = '01/01/2011 01:01:01 AM'
Get-ChildItem C:\TEMP\test.log | Select-Object CreationTime
#endregion

#region NetworkConnect: Event 3
$filter = '
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=3)]]</Select>
  </Query>
</QueryList>'

# Extra PowerShell goodness to grab the hashes
$events = Get-WinEvent -FilterXml $filter -ErrorAction SilentlyContinue -MaxEvents 100
$DestinationIPList = @()

foreach ($event in $events) {
    # Converting our data to XML
    $eventXML = [xml]$event.ToXml()
    # Grabbing just the hash
    $IPAddress = ($eventXML.Event.EventData.Data[13].'#text' -split "=")[-1]
    # Creating a list of unique hashes.  This takes the list from 2420 to 181 to test.
    if ($DestinationIPList -notcontains $IPAddress) {
        $DestinationIPList += $IPAddress
    }
}

$DestinationIPList | Out-GridView -Title "Destination IP Addresses"
<#
<NetworkConnect onmatch="include">
            <DestinationPort>8080</DestinationPort>
        </NetworkConnect>
        <NetworkConnect onmatch="exclude">
            <Image condition="contains">chrome.exe</Image>
            <Image condition="contains">GoogleUpdate.exe</Image>
            <Image condition="contains">MicrosoftEdgeCP.exe</Image>
            <Image condition="contains">Outlook.exe</Image>
            <Image condition="contains">iexplore.exe</Image>
            <Image condition="contains">firefox.exe</Image>
        </NetworkConnect>
#>
#endregion

#region Sysmon Status: Event 4
Stop-Service -Name Sysmon
Start-Service -Name Sysmon
#endregion

#region ProcessTerminate: Event 5
# ProcessGuid - forshadowing :)
Start-Process PowerShell -PassThru | Stop-Process
#endregion

#region FileCreate: Event 11
New-Item -Path C:\TEMP\ -Name test111.txt -ItemType File
#endregion

#region RegistryEvent: Event 12/13/14
# 12 = Create Key event
# 13 = Value set
# 14 = Key/Value rename

# Create a new key
$key = 'HKLM:\SOFTWARE\TEST\Meals'
If (-Not( Test-Path $Key)) {
    New-Item -Path $Key -ItemType RegistryKey -Force
}

# Check for it
$f = '<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[( (EventID &gt;= 12 and EventID &lt;= 14) )]]</Select>
  </Query>
</QueryList>'

Get-WinEvent -FilterXml $f | Select-Object -ExpandProperty message -First 1

# Set value
$key = 'HKLM:\SOFTWARE\TEST\Meals'
#$Key = "HKEY_LOCAL_MACHINE\SOFTWARE\TEST"
Set-ItemProperty -path $Key -Name 'Lunch' -Type 'String' -Value 'A big fan!'
#endregion

#region FileCreateStreamHash: Event 15
#https://collaborate.osumc.edu/it/staff/TSS/ServerTeam/scriptingblog/default.aspx

# Create a text file with a bit of text
"This is visible data" > "C:\TEMP\ads.txt"

# verify content, opens in your default text reader
Invoke-Item "C:\TEMP\ads.txt"

# View the streams, should only see the default stream
Get-Item -Path "C:\TEMP\ads.txt" -Stream *

# Create some data...
$data = @'
John Claverhouse was a moon-faced man.
You know the kind, cheek-bones wide apart,
chin and forehead melting into the cheeks to complete the perfect round,
and the nose, broad and pudgy, equidistant from the circumference,
flattened against the very centre of the face like a dough-ball upon the ceiling.
'@

# apply the data to a new stream
Set-Content -Path "C:\TEMP\ads.txt" -Stream Hidden -Value $data

# View the streams again, should see two streams
Get-Item -Path "C:\TEMP\ads.txt" -Stream *

# View the actual stream
Get-Content -Path 'C:\TEMP\ads.txt:hidden'

# More stream info
# https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs/
# https://docs.microsoft.com/en-us/sysinternals/downloads/streams
#endregion

#region WmiEvent: Event 19/20/21
<#  Create the event filter.
    In this case, looking for service modification
    As you can see, I am a big fan of splatting. #>

# define our query
$WQL = @'
    SELECT *
    FROM __instanceModificationEvent within 5
    WHERE targetInstance isa "win32_Service"
'@

# define the parameter values
$wmiParams = @{
    Computername = $env:COMPUTERNAME
    NameSpace    = 'root\subscription'
    Class        = '__EventFilter'
    Arguments    = @{
        Name           = 'Service_Filter'
        EventNamespace = 'root\CIMV2'
        QueryLanguage  = 'WQL'
        Query          = $WQL
    }
}
# create the event filter
$filter = Set-WmiInstance @wmiParams

##### Create the consumer
$wmiParams = @{
    Computername = $env:COMPUTERNAME
    NameSpace    = 'root\subscription'
    Class        = 'LogFileEventConsumer'
    Arguments    = @{
        Name     = 'Service_Consumer'
        Text     = 'A change has occurred on the service: %TargetInstance.DisplayName%'
        FileName = "C:\temp\Log.log"
    }
}
$consumer = Set-WmiInstance @wmiParams


##### Create the binding
$wmiParams = @{
    Computername = $env:COMPUTERNAME
    NameSpace    = 'root\subscription'
    Class        = '__FilterToConsumerBinding'
    Arguments    = @{
        Filter   = $filter
        Consumer = $consumer
    }
}

Set-WmiInstance @wmiParams

##Removing WMI Subscriptions using Remove-WMIObject
#Filter
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='Service_Filter'" | Remove-WmiObject -Verbose

#Consumer
Get-WMIObject -Namespace root\Subscription -Class LogFileEventConsumer -Filter "Name='Service_Consumer'" | Remove-WmiObject -Verbose

#Binding
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Service_Filter%'"  | Remove-WmiObject -Verbose

#endregion