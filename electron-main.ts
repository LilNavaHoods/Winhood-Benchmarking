/**
 * WinHood Enterprise - Desktop Windows Launcher (Electron & Hardware Acceleration)
 *
 * Permite a execução nativa no Windows (.exe) aproveitando a aceleração por GPU,
 * múltiplos núcleos de CPU para testes pesados, e integração direta com o terminal
 * e containers Docker da máquina host.
 */

import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Interfaces seguras para desacoplamento quando rodado em ambiente tsx ou Electron
interface ElectronApp {
  whenReady: () => Promise<void>;
  on: (event: string, callback: (...args: any[]) => void) => void;
  quit: () => void;
  commandLine: {
    appendSwitch: (switchName: string, value?: string) => void;
  };
}

interface BrowserWindowConstructor {
  new (options: any): {
    loadURL: (url: string) => Promise<void>;
    loadFile: (filePath: string) => Promise<void>;
    on: (event: string, callback: (...args: any[]) => void) => void;
    show: () => void;
    webContents: {
      openDevTools: () => void;
    };
  };
}

let electronModule: { app?: ElectronApp; BrowserWindow?: BrowserWindowConstructor } | null = null;

try {
  // Tentativa dinâmica de carregar electron se presente no runtime desktop
  const req = (globalThis as any).require || null;
  if (req) {
    electronModule = req('electron');
  }
} catch {
  electronModule = null;
}

export async function bootstrapWindowsDesktop() {
  const isElectronRuntime = Boolean(electronModule?.app && electronModule?.BrowserWindow);

  console.log('='.repeat(70));
  console.log('  WINHOOD ENTERPRISE - WINDOWS DESKTOP ACCELERATOR');
  console.log('='.repeat(70));
  console.log(`  Plataforma: Windows / Win32 (x64 / arm64)`);
  console.log(`  Runtime: ${isElectronRuntime ? 'Electron Native Desktop (.exe)' : 'Node.js Core Desktop Mode'}`);
  console.log(`  Aceleração de Hardware: Ativada (GPU Rasterization + Multi-Core Threads)`);
  console.log('='.repeat(70));

  if (isElectronRuntime && electronModule?.app && electronModule?.BrowserWindow) {
    const { app, BrowserWindow } = electronModule;

    // Configurações de aceleração de hardware para testes pesados
    app.commandLine.appendSwitch('enable-gpu-rasterization');
    app.commandLine.appendSwitch('enable-zero-copy');
    app.commandLine.appendSwitch('ignore-gpu-blocklist');
    app.commandLine.appendSwitch('disable-background-timer-throttling');

    await app.whenReady();

    const mainWindow = new BrowserWindow({
      width: 1440,
      height: 900,
      minWidth: 1024,
      minHeight: 700,
      backgroundColor: '#0b1120',
      title: 'WinHood Enterprise - Avaliação & Benchmark de Software',
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        preload: path.join(__dirname, 'electron-preload.js'),
      },
    });

    const targetUrl = process.env.VITE_DEV_SERVER_URL || 'http://localhost:3000';
    console.log(`Carregando interface WinHood em ${targetUrl}...`);
    await mainWindow.loadURL(targetUrl);
    mainWindow.show();

    app.on('window-all-closed', () => {
      if (process.platform !== 'darwin') {
        app.quit();
      }
    });
  } else {
    console.log('[WinHood Desktop Launcher] Modo Servidor Local ativo.');
    console.log('Para gerar o executável nativo Windows (.exe), execute: scripts/windows/build-windows-exe.bat');
  }
}

// Inicialização automática se invocado diretamente
if (process.env.WINHOOD_DESKTOP_RUN === 'true') {
  bootstrapWindowsDesktop().catch(console.error);
}
