def evaluateWinHoodGate(String targetPath = '.', String gateId = 'winhood-standard-v2') {
  def status = sh(
    script: "npx tsx cli/winhood-cli.ts gate --path ${targetPath} --gate ${gateId} --deterministic > winhood-gate.json",
    returnStatus: true
  )
  if (status == 1) {
    error("WinHood Quality Gate BLOCKED/REJECTED merge/release (exitCode=1)")
  }
  if (status == 2) {
    currentBuild.result = 'UNSTABLE'
    echo "WinHood Quality Gate INCONCLUSIVE (exitCode=2)"
  }
  if (status >= 3) {
    error("WinHood execution failed (exitCode=${status})")
  }
  return status
}
return this
