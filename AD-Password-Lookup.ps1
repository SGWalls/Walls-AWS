# AD User Password Lookup Script
# Compares password last set times between TMK and INT domains

$tmkUsers = Get-ADUser -Filter * -Properties passwordlastset | Select-Object name, samaccountname, passwordlastset

$results = foreach ($user in $tmkUsers) {
    try {
        $intUser = Get-ADUser $user.samaccountname -Properties passwordlastset -Server int.globelifeinc.com -ErrorAction Stop
        [PSCustomObject]@{
            Name = $user.name
            UserName = $user.samaccountname
            'TMK PWD Set Time' = $user.passwordlastset
            'INT PWD Set Time' = $intUser.passwordlastset
        }
    }
    catch {
        [PSCustomObject]@{
            Name = $user.name
            UserName = $user.samaccountname
            'TMK PWD Set Time' = $user.passwordlastset
            'INT PWD Set Time' = "Not Found/Error"
        }
    }
}

$results | Format-Table -AutoSize