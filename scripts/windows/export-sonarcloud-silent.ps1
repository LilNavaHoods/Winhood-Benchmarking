<#
.SYNOPSIS
  Script de Extração Silenciosa em Segundo Plano de Relatório JSON do SonarCloud
.DESCRIPTION
  Executa a paginação e agregação determinística de Issues, Quality Gate, Métricas
  e Hotspots diretamente na API oficial do SonarCloud sem exibir janelas interativas.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$ProjectKey,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile = ""
)

$ErrorActionPreference = "Stop"
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Accept"        = "application/json"
    "User-Agent"    = "WinHood-SonarCloudSilentExtractor/2.0"
}

$EncodedOrg = [System.Uri]::EscapeDataString($Organization.Trim())
$EncodedKey = [System.Uri]::EscapeDataString($ProjectKey.Trim())
$BaseUrl = "https://sonarcloud.io"

try {
    # 1. Quality Gate Status
    $QGUrl = "$BaseUrl/api/qualitygates/project_status?projectKey=$EncodedKey"
    $QGRes = Invoke-RestMethod -Uri $QGUrl -Headers $Headers -Method Get -TimeoutSec 15
    $ProjectStatus = $QGRes.projectStatus

    # 2. Component Measures
    $MetricKeys = "bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,ncloc,sqale_index,sqale_rating,reliability_rating,security_rating,security_review_rating,alert_status,complexity,cognitive_complexity"
    $MeasuresUrl = "$BaseUrl/api/measures/component?component=$EncodedKey&metricKeys=$MetricKeys"
    $MeasuresRes = Invoke-RestMethod -Uri $MeasuresUrl -Headers $Headers -Method Get -TimeoutSec 15
    $Measures = $MeasuresRes.component.measures

    # 3. Security Hotspots
    $HotspotsUrl = "$BaseUrl/api/hotspots/search?projectKey=$EncodedKey&ps=500"
    $HotspotsRes = Invoke-RestMethod -Uri $HotspotsUrl -Headers $Headers -Method Get -TimeoutSec 15
    $Hotspots = $HotspotsRes.hotspots

    # 4. Paging Issues
    $AllIssues = [System.Collections.Generic.List[object]]::new()
    $Page = 1
    $PageSize = 500
    $TotalIssues = 0

    do {
        $IssuesUrl = "$BaseUrl/api/issues/search?organization=$EncodedOrg&componentKeys=$EncodedKey&ps=$PageSize&p=$Page&additionalFields=_all&facets=severities,types,rules,statuses"
        $IssuesRes = Invoke-RestMethod -Uri $IssuesUrl -Headers $Headers -Method Get -TimeoutSec 20
        $TotalIssues = $IssuesRes.total
        if ($IssuesRes.issues) {
            foreach ($issue in $IssuesRes.issues) {
                $AllIssues.Add($issue)
            }
        }
        $Page++
    } while ($AllIssues.Count -lt $TotalIssues -and $Page -le 20)

    # 5. Build Aggregated JSON
    $Report = [PSCustomObject]@{
        schemaVersion = "1.0.0"
        extractedAt   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        platform      = "SONARCLOUD"
        serverUrl     = "https://sonarcloud.io"
        organization  = $Organization.Trim()
        projectKey    = $ProjectKey.Trim()
        qualityGate   = $ProjectStatus
        measures      = $Measures
        hotspots      = $Hotspots
        totalIssues   = $AllIssues.Count
        issues        = $AllIssues
    }

    $JsonOutput = $Report | ConvertTo-Json -Depth 100

    if ($OutputFile -and $OutputFile.Trim().Length -gt 0) {
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputFile, $JsonOutput, $Utf8NoBom)
    } else {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Write-Output $JsonOutput
    }
}
finally {
    # Limpeza estrita de variáveis em memória
    $Token = $null
    $Headers = $null
    [System.GC]::Collect()
}
