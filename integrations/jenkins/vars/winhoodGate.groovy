def call(Map config = [:]) {
  String targetPath = config.get('path', '.')
  String gate = config.get('gate', 'winhood-standard-v2')
  String failOn = config.get('failOn', 'BLOCKED')

  int exitCode = sh(
    script: "npx tsx cli/winhood-cli.ts gate --path '${targetPath}' --gate '${gate}' --ci-exit-codes --deterministic > winhood-gate.json",
    returnStatus: true
  )
  archiveArtifacts artifacts: 'winhood-gate.json', allowEmptyArchive: true

  if (exitCode == 2) {
    error("WinHood Quality Gate BLOCKED/REJECTED (canonical exitCode=2)")
  } else if (exitCode == 1 && failOn == 'APPROVED_WITH_RESERVATIONS') {
    error("WinHood Quality Gate APPROVED_WITH_RESERVATIONS blocked by strict policy (exitCode=1)")
  } else if (exitCode == 1) {
    unstable("WinHood Quality Gate APPROVED_WITH_RESERVATIONS (exitCode=1)")
  } else if (exitCode == 3) {
    unstable("WinHood Quality Gate INCONCLUSIVE (exitCode=3)")
  } else if (exitCode >= 4) {
    error("WinHood execution error (exitCode=${exitCode})")
  }
  return exitCode
}
