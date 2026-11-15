def call(Map config = [:]) {
  String targetPath = config.get('path', '.')
  String profile = config.get('profile', 'mqr-strict')
  String gate = config.get('gate', 'winhood-standard-v2')
  String format = config.get('format', 'sarif')
  String outFile = config.get('out', "winhood-report.${format}")

  sh "npx tsx cli/winhood-cli.ts report --path '${targetPath}' --profile '${profile}' --gate '${gate}' --format='${format}' --deterministic --out '${outFile}'"
  archiveArtifacts artifacts: outFile, allowEmptyArchive: false
  return outFile
}
