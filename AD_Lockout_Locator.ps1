$UserName = Read-Host -Prompt 'Please enter username'
  $DaysToSearch = Read-Host -Prompt 'Please enter how many days to search prior to today'
  $ComputerName = (Get-ADDomainController -Filter * |  Select-Object -ExpandProperty Name)


        Foreach ($Computer in $ComputerName) {
          #Get user info
          $UserInfo = Get-ADUser -Identity $UserName
          #Search PDC for lockout events with ID 47
          $LockedOutEvents = Get-WinEvent -ComputerName $Computer -FilterHashtable @{LogName='Security';Id=4740;StartTime = (Get-Date).AddDays(-$DaysToSearch)} -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Descending
          #Parse and filter out lockout events
          Foreach($Event in $LockedOutEvents)
          {
            If($Event | Where-Object {$_.Properties[2].value -match $UserInfo.SID.Value})
            {

              $Event | Select-Object -Property @(
                @{Label = 'User'; Expression = {$_.Properties[0].Value}}
                @{Label = 'DomainController'; Expression = {$_.MachineName}}
                @{Label = 'LockoutTimeStamp'; Expression = {$_.TimeCreated}}
                @{Label = 'Message'; Expression = {$_.Message -split "`r" | Select-Object -First 1}}
                @{Label = 'LockoutSource'; Expression = {$_.Properties[1].Value}}
              )


            }
          }
          }
