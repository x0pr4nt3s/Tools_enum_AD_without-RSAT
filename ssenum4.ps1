<#
Enumerar cantidad de los usuarios activos e inactivos 
echo "------------------------------------------"
$length_all_users=(Get-ADUser -Filter * -Properties * | Select SamAccountName).length;
echo "Total de Usuarios : $length_all_users"
echo "-------------------------------------------"
#>
<#
Enumerar cantidad de usuarios activos : 
$length_active_users=(Get-ADUser -Filter * -Properties * | ?{$_.Enabled -eq "true" } | Select SamAccountName).length;
echo "Usuarios Activos : $length_active_users"
echo "-------------------------------------------"
#>
<#
Enumeracion de todos los usuarios
#>
Get-ADUser -Filter * -Properties * | Select SamAccountName,UserPrincipalName,EmailAddress,Description,PasswordExpired,PrimaryGroup,PasswordLastSet,LastLogonDate,Enabled,PasswordNotRequired,DistinguishedName,@{N='MemberOf';E={$_.'MemberOf'}} | export-csv Domain_Users.csv

<#
Enumeracion de todos los grupos
#>
Get-ADGroup -Filter * -Properties * | Select SamAccountName,Description,Modified,isDeleted,DistinguishedName | export-csv domain_groups.csv

<#
Enumeracion de todas las computadoras
#>
Get-ADComputer -Filter * -Properties * | Select SamAccountName,OperatingSystem,Ipv4Address,Ipv6Address,LastLogonDate,PrimaryGroup,DNSHostName,Enabled | Export-csv domain_computers.csv














