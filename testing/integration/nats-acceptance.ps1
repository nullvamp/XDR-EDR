$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
function Assert($condition,[string]$message){if(-not $condition){throw "FAIL: $message"};Write-Host "PASS $message"}
function NatsBox([string[]]$arguments){$strict=$ErrorActionPreference;$ErrorActionPreference='Continue';$result=docker run --rm --network deployment_platform natsio/nats-box:0.19.2 nats --server nats://nats:4222 @arguments 2>&1;$exit=$LASTEXITCODE;$ErrorActionPreference=$strict;if($exit-ne 0){throw "NATS CLI failed: $result"};$result}
function NatsJson([string[]]$arguments){$text=NatsBox $arguments|Out-String;$start=$text.IndexOf('{');$end=$text.LastIndexOf('}');if($start-lt 0-or$end-lt$start){throw "NATS CLI did not return JSON: $text"};$text.Substring($start,$end-$start+1)|ConvertFrom-Json}
function StreamMessages{$info=NatsJson @('stream','info','PLATFORM_ENDPOINTS','--json');[long]$info.state.messages}

$messageId=[guid]::NewGuid().ToString('N')
$endpointId=[guid]::NewGuid()
$subject="platform.acceptance.duplicate.$messageId"
$payload=@{Type='endpoint.acceptance';Version='1.0';Id=$messageId;TenantId='00000000-0000-0000-0000-000000000002';OccurredAt=[DateTimeOffset]::UtcNow.ToString('o');Data=@{endpointId=$endpointId};TraceId=$messageId}|ConvertTo-Json -Compress
$before=StreamMessages
NatsBox @('pub',$subject,$payload,'--jetstream','--header',"Nats-Msg-Id:$messageId")|Out-Null
NatsBox @('pub',$subject,$payload,'--jetstream','--header',"Nats-Msg-Id:$messageId")|Out-Null
$after=StreamMessages
Assert ($after-$before -eq 1) 'JetStream deduplicates duplicate event delivery by message ID'

$consumer="redelivery-$($messageId.Substring(0,12))"
$redeliverySubject="platform.acceptance.redelivery.$messageId"
try{
  NatsBox @('consumer','add','PLATFORM_ENDPOINTS',$consumer,'--pull','--ack','explicit','--wait','1s','--max-deliver','2','--deliver','new','--filter',$redeliverySubject,'--defaults')|Out-Null
  $redeliveryPayload=@{Type='endpoint.acceptance';Version='1.0';Id=[guid]::NewGuid().ToString('N');TenantId='00000000-0000-0000-0000-000000000002';OccurredAt=[DateTimeOffset]::UtcNow.ToString('o');Data=@{endpointId=[guid]::NewGuid()};TraceId=$messageId}|ConvertTo-Json -Compress
  NatsBox @('pub',$redeliverySubject,$redeliveryPayload,'--jetstream')|Out-Null
  NatsBox @('consumer','next','PLATFORM_ENDPOINTS',$consumer,'--count','1','--no-ack','--wait','2s')|Out-Null
  Start-Sleep 2
  NatsBox @('consumer','next','PLATFORM_ENDPOINTS',$consumer,'--count','1','--ack','--wait','3s')|Out-Null
  $info=NatsJson @('consumer','info','PLATFORM_ENDPOINTS',$consumer,'--json')
  Assert ($info.delivered.consumer_seq -eq 2 -and $info.ack_floor.consumer_seq -eq 2) 'JetStream redelivers an unacknowledged message and accepts the later ACK'
}finally{NatsBox @('consumer','rm','PLATFORM_ENDPOINTS',$consumer,'--force')|Out-Null}
Write-Host 'NATS duplicate and redelivery acceptance suite passed.'
