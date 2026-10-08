param(
    [Parameter(Mandatory, Position=0)][string]$PaoPath,
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$PaoArguments
)
$ErrorActionPreference = 'Stop'
& $PaoPath @PaoArguments
exit $LASTEXITCODE
