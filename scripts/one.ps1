[CmdletBinding()]
param(
  [Parameter(Position = 0)] [string]$Command = 'help',
  [string]$CliPath = '',
  [string]$StateDir = '',
  [string]$Handoff = '',
  [string]$GatewayId = '',
  [string]$NetworkId = '',
  [string]$DeviceId = '',
  [string]$Name = '',
  [switch]$InviteStdin,
  [switch]$Bootstrap
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$Message) { throw "one.ps1: $Message" }

function Usage {
  @'
Usage:
  .\one.ps1 join -GatewayId ID -Handoff FILE -InviteStdin
  .\one.ps1 sync | status | diagnose | down

The Windows One wrapper reads one short-lived xconnect://join/... invitation
from stdin. It does not read Vault or save the invitation.
'@
}

function Require-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run PowerShell as Administrator'
  }
}

function Resolve-Cli {
  if (-not $script:CliPath) {
    $script:CliPath = Join-Path $env:ProgramFiles 'XConnect\xconnect-windows-amd64.exe'
  }
  if (-not (Test-Path -LiteralPath $script:CliPath -PathType Leaf)) {
    Fail "xconnect binary not found: $script:CliPath"
  }
}

function Resolve-Defaults {
  if (-not $script:StateDir) { $script:StateDir = Join-Path $env:ProgramData 'XConnect-One' }
  if (-not $script:DeviceId) { $script:DeviceId = "one-windows-$($env:COMPUTERNAME.ToLowerInvariant())" }
  if (-not $script:Name) { $script:Name = "XConnect One $script:DeviceId" }
}

function Read-Handoff {
  if (-not $script:Handoff) { return }
  if (-not (Test-Path -LiteralPath $script:Handoff -PathType Leaf)) { Fail "handoff not found: $script:Handoff" }
  $handoff = Get-Content -Raw -LiteralPath $script:Handoff | ConvertFrom-Json
  if (-not $script:GatewayId) { $script:GatewayId = $handoff.gateway_id }
  if ($script:GatewayId -ne $handoff.gateway_id) { Fail 'selected Gateway does not match handoff' }
  if (-not $script:NetworkId) { $script:NetworkId = $handoff.network_id }
  if ($script:NetworkId -ne $handoff.network_id) { Fail 'selected network does not match handoff' }
  if ($handoff.gateway_endpoint.transport -ne 'vless-xhttp' -or [int]$handoff.gateway_endpoint.port -ne 443) {
    Fail 'handoff must use VLESS/XHTTP TCP 443'
  }
  if ($handoff.gateway_endpoint.host -ne 'tw-xconnect.svc.plus') { Fail 'handoff Gateway host is invalid' }
}

function Invoke-One([string]$Subcommand, [string[]]$Arguments = @()) {
  Resolve-Cli
  Resolve-Defaults
  & $script:CliPath $Subcommand '--state-dir' $script:StateDir @Arguments
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Command.ToLowerInvariant()) {
  'help' { Usage; exit 0 }
  'join' {
    Require-Administrator
    Resolve-Cli
    Resolve-Defaults
    Read-Handoff
    if (-not $script:GatewayId) { Fail '-GatewayId is required' }
    if (-not $script:NetworkId) { Fail '-NetworkId or -Handoff is required' }
    if (-not $InviteStdin) { Fail 'join requires -InviteStdin' }
    $invite = [Console]::In.ReadLine()
    if (-not $invite.StartsWith('xconnect://join/')) { Fail 'stdin must contain one xconnect://join/... invitation' }
    New-Item -ItemType Directory -Force -Path $script:StateDir | Out-Null
    Write-Output "[1/4] join: device=$script:DeviceId network=$script:NetworkId gateway=$script:GatewayId"
    $joinArgs = @('--device-id', $script:DeviceId, '--name', $script:Name, '--network-id', $script:NetworkId)
    if ($Bootstrap) { $joinArgs = @('--bootstrap') + $joinArgs }
    Invoke-One 'join' ($joinArgs + $invite)
    Write-Output '[2/4] sync: apply signed config and send ACK'
    Invoke-One 'sync'
    Write-Output '[3/4] status'
    Invoke-One 'status'
    Write-Output '[4/4] diagnose'
    Invoke-One 'diagnose'
    Write-Output 'PASS: XConnect One enrolled and local runtime applied.'
  }
  'sync' { Require-Administrator; Invoke-One 'sync' }
  'status' { Require-Administrator; Invoke-One 'status' }
  'diagnose' { Require-Administrator; Invoke-One 'diagnose' }
  'down' { Require-Administrator; Invoke-One 'down' }
  default { Fail "unknown command: $Command (use help)" }
}
