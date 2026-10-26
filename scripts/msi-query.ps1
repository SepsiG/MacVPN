# Runs one SQL query against an MSI's tables and prints the rows, one per line, columns separated by a tab.
# Read-only (the database is opened with msiOpenDatabaseModeReadOnly); needs no administrator rights and installs
# nothing. Used by scripts/build-msi.sh's MSI gates.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/msi-query.ps1 MSI "SELECT `Value` FROM `Property` WHERE `Property`='UpgradeCode'"
param([Parameter(Mandatory = $true)][string]$Msi, [Parameter(Mandatory = $true)][string]$Query)
$ErrorActionPreference = 'Stop'

function Invoke($target, [string]$name, [object[]]$arguments, [System.Reflection.BindingFlags]$kind) {
  $target.GetType().InvokeMember($name, $kind, $null, $target, $arguments)
}
$call = [System.Reflection.BindingFlags]::InvokeMethod
$get = [System.Reflection.BindingFlags]::GetProperty

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = Invoke $installer 'OpenDatabase' @((Resolve-Path -LiteralPath $Msi).Path, 0) $call
$view = Invoke $database 'OpenView' @($Query) $call
Invoke $view 'Execute' @() $call | Out-Null
$columns = Invoke (Invoke $view 'ColumnInfo' @(0) $get) 'FieldCount' @() $get
$out = New-Object System.Collections.Generic.List[string]
while ($true) {
  $record = Invoke $view 'Fetch' @() $call
  if ($null -eq $record) { break }
  $fields = for ($i = 1; $i -le $columns; $i++) { Invoke $record 'StringData' @($i) $get }
  $out.Add(($fields -join "`t"))
}
Invoke $view 'Close' @() $call | Out-Null
[Console]::Out.Write((($out | ForEach-Object { $_ + "`n" }) -join ''))
