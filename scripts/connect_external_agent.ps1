param(
    [ValidateSet('codex','claude','ollama')][string]$Client='codex',
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')][string]$SessionName,
    [string]$Model,
    [ValidateSet('memory','secret','persistence','network','processes','privileges','workflow','injection')][string]$Level,
    [ValidateSet('workflow,processes')][string]$Journey,
    [string]$ScenarioId,
    [ValidateRange(1,600)][int]$CommandSeconds=60,
    # Rehearsal limits (provisional bounds). Container profile is never widened.
    # Omitted values keep each connector's own default (Claude and Ollama 64/64, Codex 32/32; lease 3600; MCP max(180, CommandSeconds+120)).
    [ValidateRange(1,256)][int]$MaxCommands,
    [ValidateRange(1,256)][int]$MaxPolicyRequests,
    [ValidateRange(60,14400)][int]$SessionSeconds,
    [ValidateRange(30,1800)][int]$McpToolSeconds,
    [ValidateSet('invitation','missing-data')][string]$Scenario='invitation',
    [switch]$CheckOnly,[switch]$AllowRoomTools,[switch]$GrantCatalog,[switch]$Recover,[switch]$PublishOnly
)
$ErrorActionPreference='Stop'
if($Level -and $Journey){throw 'Select one level or one journey.'}
$taskRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ($GrantCatalog) { & (Join-Path $PSScriptRoot 'grant_external_catalog.ps1') -SessionName $SessionName; exit }
$taskPython=(Get-Command python.exe -ErrorAction Stop).Source
$taskFolder=Join-Path $taskRoot ('.private/external-agent/'+$SessionName)
if ($Recover) {
    & $taskPython -X utf8 (Join-Path $PSScriptRoot 'recover_external_session.py') --db (Join-Path $taskFolder 'bridge-state.sqlite3') --report (Join-Path $taskFolder ('recovery-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')) --operator-control-dir $taskFolder
    exit $LASTEXITCODE
}
if ($PublishOnly) {
    & $taskPython -X utf8 (Join-Path $PSScriptRoot 'publish_external_trace.py') --session-name $SessionName
    exit $LASTEXITCODE
}
if ($Client -eq 'codex') {
    $taskArgs=@{SessionName=$SessionName;Scenario=$Scenario;ObserveState='all'}
    if ($CheckOnly) {$taskArgs.CheckOnly=$true}
    if ($Level) {$taskArgs.Level=$Level}
    if ($Journey) {$taskArgs.Journey=$Journey}
    if($ScenarioId){$taskArgs.ScenarioId=$ScenarioId}
    $taskArgs.CommandSeconds=$CommandSeconds
    if ($PSBoundParameters.ContainsKey('MaxCommands')) {$taskArgs.MaxCommands=$MaxCommands}
    if ($PSBoundParameters.ContainsKey('MaxPolicyRequests')) {$taskArgs.MaxPolicyRequests=$MaxPolicyRequests}
    if ($PSBoundParameters.ContainsKey('SessionSeconds')) {$taskArgs.SessionSeconds=$SessionSeconds}
    if ($PSBoundParameters.ContainsKey('McpToolSeconds')) {$taskArgs.McpTimeoutSeconds=$McpToolSeconds}
    if ($Model) {$taskArgs.Model=$Model}
    & (Join-Path $PSScriptRoot 'connect_external_codex.ps1') @taskArgs
    exit $LASTEXITCODE
}
$taskArgs=@('-X','utf8',(Join-Path $PSScriptRoot ('connect_external_'+$Client+'.py')),'--session-name',$SessionName,'--scenario',$Scenario,'--observe-state','all')
$taskArgs+=@('--command-seconds',[string]$CommandSeconds)
if ($PSBoundParameters.ContainsKey('MaxCommands')) {$taskArgs+=@('--max-commands',[string]$MaxCommands)}
if ($PSBoundParameters.ContainsKey('MaxPolicyRequests')) {$taskArgs+=@('--max-policy-requests',[string]$MaxPolicyRequests)}
if ($PSBoundParameters.ContainsKey('SessionSeconds')) {$taskArgs+=@('--session-seconds',[string]$SessionSeconds)}
if ($PSBoundParameters.ContainsKey('McpToolSeconds')) {$taskArgs+=@('--mcp-tool-seconds',[string]$McpToolSeconds)}
if ($Model) {$taskArgs+=@('--model',$Model)} elseif ($Client -eq 'ollama') {throw 'Ollama requires -Model with an installed local model.'}
if ($Level) {$taskArgs+=@('--level',$Level)}
if ($Journey) {
    $taskArgs+=@('--journey',$Journey)
}
if ($ScenarioId) {$taskArgs+=@('--scenario-id',$ScenarioId)}
if ($CheckOnly) {$taskArgs+='--check-only'}
if ($AllowRoomTools) {$taskArgs+='--allow-room-tools'}
& $taskPython @taskArgs
exit $LASTEXITCODE
