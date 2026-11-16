var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// electron-preload.ts
var electron_preload_exports = {};
__export(electron_preload_exports, {
  createWinHoodPreloadBridge: () => createWinHoodPreloadBridge
});
module.exports = __toCommonJS(electron_preload_exports);
var import_node_module = require("node:module");
var import_meta = {};
var ALLOWED_CHANNELS = /* @__PURE__ */ new Set([
  "winhood:get-runtime-info",
  "winhood:get-backend-health",
  "winhood:open-logs-folder"
]);
function invokeAllowedChannel(ipcRenderer, channel, payload) {
  if (!ALLOWED_CHANNELS.has(channel)) {
    return Promise.reject(new Error(`IPC_CHANNEL_FORBIDDEN: ${channel}`));
  }
  return ipcRenderer.invoke(channel, payload ?? {});
}
function createWinHoodPreloadBridge(ipcRenderer) {
  return Object.freeze({
    isElectronDesktop: true,
    getRuntimeInfo: () => invokeAllowedChannel(ipcRenderer, "winhood:get-runtime-info"),
    getBackendHealth: () => invokeAllowedChannel(ipcRenderer, "winhood:get-backend-health"),
    openLogsFolder: () => invokeAllowedChannel(ipcRenderer, "winhood:open-logs-folder")
  });
}
try {
  const req = typeof require === "function" ? require : (0, import_node_module.createRequire)(typeof __filename !== "undefined" ? __filename : import_meta.url);
  const electron = req("electron");
  if (electron?.contextBridge && electron?.ipcRenderer) {
    const bridge = createWinHoodPreloadBridge(electron.ipcRenderer);
    electron.contextBridge.exposeInMainWorld("winhoodDesktop", bridge);
  }
} catch {
}
// Annotate the CommonJS export names for ESM import in node:
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
  createWinHoodPreloadBridge
};
}
