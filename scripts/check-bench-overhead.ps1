# check-bench-overhead.ps1 — assert mean(benchA) - mean(benchB) <= max_ns.
#
# Usage: pwsh ./scripts/check-bench-overhead.ps1 <bench_hooked> <bench_bare> <max_overhead_ns>
#
# Reads target/criterion/<bench>/base/estimates.json for both benches,
# parses mean.point_estimate, and exits 0 iff
#   mean(hooked) - mean(bare) <= max_overhead_ns
# else exits 1.
#
# Used by H-A4 to gate hook overhead in absolute nanoseconds. We measure
# absolute overhead rather than ratio because the bare baseline at the
# closure-invocation layer (~300 ns to return a struct) makes any ratio
# unstable: a 1 microsecond hook tax shows up as ~3x ratio yet is
# negligible in any real MCP request where transport+JSON dominate (tens
# of microseconds minimum).

param(
    [Parameter(Mandatory=$true)][string]$BenchHooked,
    [Parameter(Mandatory=$true)][string]$BenchBare,
    [Parameter(Mandatory=$true)][double]$MaxOverheadNs
)

$ErrorActionPreference = 'Stop'

function Get-MeanNs([string]$benchName) {
    $path = Join-Path -Path 'target' -ChildPath "criterion/$benchName/base/estimates.json"
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Error "ERROR: $path not found. Run 'cargo bench' first."
        exit 1
    }
    $json = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    return [double]$json.mean.point_estimate
}

$hooked = Get-MeanNs $BenchHooked
$bare = Get-MeanNs $BenchBare
$overhead = $hooked - $bare

if ($overhead -le $MaxOverheadNs) {
    Write-Output ("PASS: {0} - {1} overhead={2:N1} ns <= {3:N1} ns (means: {4:N1} ns / {5:N1} ns)" -f `
        $BenchHooked, $BenchBare, $overhead, $MaxOverheadNs, $hooked, $bare)
    exit 0
} else {
    Write-Error ("FAIL: {0} - {1} overhead={2:N1} ns > {3:N1} ns (means: {4:N1} ns / {5:N1} ns)" -f `
        $BenchHooked, $BenchBare, $overhead, $MaxOverheadNs, $hooked, $bare)
    exit 1
}
