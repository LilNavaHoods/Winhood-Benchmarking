package io.winhood.intellij

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

class WinHoodAuditAction : AnAction() {
  override fun actionPerformed(e: AnActionEvent) {
    val project = e.project ?: return
    val basePath = project.basePath ?: return
    val rootDir = File(basePath)
    val filesJsonEntries = mutableListOf<String>()

    rootDir.walkTopDown()
      .filter { it.isFile && it.length() < 262_144 && !it.path.contains("node_modules") && !it.path.contains(".git") }
      .take(120)
      .forEach { file ->
        val rel = rootDir.toPath().relativize(file.toPath()).toString().replace("\\", "/")
        val escaped = file.readText()
          .replace("\\", "\\\\")
          .replace("\"", "\\\"")
          .replace("\n", "\\n")
          .replace("\r", "")
        filesJsonEntries.add("\"$rel\":\"$escaped\"")
      }

    val apiBase = System.getenv("WINHOOD_API_URL") ?: "http://localhost:3000"
    val body = """{"softwareName":"${project.name}","gateId":"winhood-standard-v2","filesMap":{${filesJsonEntries.joinToString(",")}}}"""

    val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
    val req = HttpRequest.newBuilder()
      .uri(URI.create("$apiBase/api/analyze/sarif"))
      .header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(body))
      .build()

    val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
    val type = if (resp.statusCode() in 200..299) NotificationType.INFORMATION else NotificationType.ERROR
    NotificationGroupManager.getInstance()
      .getNotificationGroup("WinHood Notifications")
      .createNotification("WinHood Audit (${resp.statusCode()})", resp.body().take(320), type)
      .notify(project)
  }
}
