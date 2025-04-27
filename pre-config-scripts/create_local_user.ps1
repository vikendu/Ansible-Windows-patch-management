$username = "ansible"
$password = ConvertTo-SecureString "ansible" -AsPlainText -Force

New-LocalUser -Name $username -Password $password -PasswordNeverExpires:$true
Add-LocalGroupMember -Group "Administrators" -Member $username