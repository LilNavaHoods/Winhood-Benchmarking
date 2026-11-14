# WinHood JetBrains Plugin (IntelliJ IDEA / WebStorm / PyCharm / GoLand)

Provides a Tools menu action that submits the active workspace to `/api/analyze/sarif`, parses SARIF 2.1.0 results, and displays the versioned Quality Gate outcome inside JetBrains IDEs.

## Files
- `src/main/resources/META-INF/plugin.xml` — IntelliJ Platform plugin descriptor.
- `src/main/kotlin/io/winhood/intellij/WinHoodAuditAction.kt` — `AnAction` calling `POST http://localhost:3000/api/analyze/sarif`.
