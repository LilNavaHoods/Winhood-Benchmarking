import zlib from 'node:zlib';
import { sanitizeUploadedFilesMap } from '../engine/staticAnalyzer';

export const MAX_ZIP_ENTRIES = 2000;
export const MAX_ENTRY_UNCOMPRESSED_BYTES = 2 * 1024 * 1024;
export const MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024;
export const MAX_COMPRESSION_RATIO = 100;
export const MIN_COMPRESSED_BYTES_FOR_RATIO_CHECK = 1024;

export interface ZipExtractionResult {
  filesMap: Record<string, string>;
  skippedCount: number;
}

export function hasExplicitPathTraversalOrSymlinkAttempt(
  rawFilesMap: Record<string, string>
): boolean {
  for (const [rawPath, content] of Object.entries(rawFilesMap || {})) {
    const normalized = rawPath.replace(/\\/g, '/');
    const segments = normalized.split('/').filter(Boolean);
    if (
      /^[a-zA-Z]:\//.test(normalized) ||
      segments.includes('..') ||
      normalized.includes('../') ||
      normalized.includes('..\\') ||
      segments.length > 20 ||
      (typeof content === 'string' && content.startsWith('SYMLINK:'))
    ) {
      return true;
    }
  }
  return false;
}

function assertSafeZipEntryName(entryName: string): void {
  if (
    entryName.includes('\0') ||
    entryName.startsWith('/') ||
    entryName.startsWith('\\') ||
    hasExplicitPathTraversalOrSymlinkAttempt({ [entryName]: '' })
  ) {
    throw new Error(`ZIP_PATH_TRAVERSAL_BLOCKED: Entrada ZIP insegura bloqueada (${entryName}).`);
  }
}

function assertSafeCompressionRatio(
  entryName: string,
  compressedSize: number,
  uncompressedSize: number
): void {
  if (
    compressedSize >= MIN_COMPRESSED_BYTES_FOR_RATIO_CHECK &&
    uncompressedSize / compressedSize >= MAX_COMPRESSION_RATIO
  ) {
    const ratio = Math.round((uncompressedSize / compressedSize) * 10) / 10;
    throw new Error(
      `ZIP_BOMB_BLOCKED: Taxa de compressão suspeita (${ratio}x >= ${MAX_COMPRESSION_RATIO}x) na entrada ${entryName}.`
    );
  }
}

function inflateZipEntrySafe(
  entryName: string,
  compressionMethod: number,
  slice: Buffer,
  declaredCompressedSize: number
): Buffer | null {
  if (compressionMethod === 0) {
    return slice;
  }
  if (compressionMethod !== 8) {
    return null;
  }
  try {
    const decoded = zlib.inflateRawSync(slice, {
      maxOutputLength: MAX_ENTRY_UNCOMPRESSED_BYTES,
    });
    const effectiveCompressedSize = Math.max(declaredCompressedSize, slice.byteLength);
    assertSafeCompressionRatio(entryName, effectiveCompressedSize, decoded.byteLength);
    return decoded;
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith('ZIP_BOMB_BLOCKED')) {
      throw err;
    }
    const errCode = (err as NodeJS.ErrnoException | undefined)?.code;
    if (errCode === 'ERR_BUFFER_TOO_LARGE') {
      throw new Error(
        `ZIP_BOMB_BLOCKED: Entrada ${entryName} excedeu o limite máximo descompactado de ${MAX_ENTRY_UNCOMPRESSED_BYTES} bytes durante a descompressão.`,
        { cause: err }
      );
    }
    return null;
  }
}

interface ZipExtractionState {
  rawExtracted: Record<string, string>;
  skippedBinaryOrInvalid: number;
  processedEntries: number;
  totalUncompressedBytes: number;
}

function processZipEntryPayload(
  state: ZipExtractionState,
  entryName: string,
  compressionMethod: number,
  compressedSize: number,
  uncompressedSize: number,
  slice: Buffer
): void {
  if (state.totalUncompressedBytes + uncompressedSize > MAX_TOTAL_UNCOMPRESSED_BYTES) {
    throw new Error(
      `ZIP_BOMB_BLOCKED: Volume cumulativo descompactado excede o limite de ${MAX_TOTAL_UNCOMPRESSED_BYTES} bytes (64MB).`
    );
  }
  const decodedBuf = inflateZipEntrySafe(entryName, compressionMethod, slice, compressedSize);
  if (!decodedBuf) {
    state.skippedBinaryOrInvalid += 1;
    return;
  }
  state.totalUncompressedBytes += decodedBuf.byteLength;
  if (state.totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
    throw new Error(
      `ZIP_BOMB_BLOCKED: Volume cumulativo descompactado excedeu o limite de ${MAX_TOTAL_UNCOMPRESSED_BYTES} bytes (64MB).`
    );
  }
  const text = decodedBuf.toString('utf8');
  if (text.includes('\0')) {
    state.skippedBinaryOrInvalid += 1;
    return;
  }
  state.rawExtracted[entryName] = text;
}

function shouldSkipOversizedEntry(
  entryName: string,
  compressionMethod: number,
  compressedSize: number,
  uncompressedSize: number
): boolean {
  if (uncompressedSize <= MAX_ENTRY_UNCOMPRESSED_BYTES) return false;
  if (
    compressionMethod === 8 &&
    compressedSize > 0 &&
    uncompressedSize / compressedSize >= MAX_COMPRESSION_RATIO
  ) {
    throw new Error(
      `ZIP_BOMB_BLOCKED: Entrada ${entryName} excede o limite individual com alta taxa de compressão.`
    );
  }
  return true;
}

function extractViaCentralDirectory(
  zipBuffer: Buffer,
  eocdOffset: number,
  state: ZipExtractionState
): void {
  const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
  if (totalEntries > MAX_ZIP_ENTRIES) {
    throw new Error(
      `ZIP_BOMB_BLOCKED: Arquivo ZIP declara ${totalEntries} entradas (limite máximo: ${MAX_ZIP_ENTRIES}).`
    );
  }
  const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
  let ptr = cdOffset;
  for (let idx = 0; idx < totalEntries && ptr + 46 <= zipBuffer.length; idx++) {
    if (zipBuffer.readUInt32LE(ptr) !== 0x02014b50) break;
    state.processedEntries += 1;
    if (state.processedEntries > MAX_ZIP_ENTRIES) {
      throw new Error(
        `ZIP_BOMB_BLOCKED: Quantidade de entradas ZIP excedeu o limite máximo (${MAX_ZIP_ENTRIES}).`
      );
    }
    const compressionMethod = zipBuffer.readUInt16LE(ptr + 10);
    const compressedSize = zipBuffer.readUInt32LE(ptr + 20);
    const uncompressedSize = zipBuffer.readUInt32LE(ptr + 24);
    const fileNameLen = zipBuffer.readUInt16LE(ptr + 28);
    const extraLen = zipBuffer.readUInt16LE(ptr + 30);
    const commentLen = zipBuffer.readUInt16LE(ptr + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(ptr + 42);
    const entryName = zipBuffer.subarray(ptr + 46, ptr + 46 + fileNameLen).toString('utf8');
    ptr += 46 + fileNameLen + extraLen + commentLen;

    if (!entryName || entryName.endsWith('/')) continue;
    assertSafeZipEntryName(entryName);
    assertSafeCompressionRatio(entryName, compressedSize, uncompressedSize);

    if (shouldSkipOversizedEntry(entryName, compressionMethod, compressedSize, uncompressedSize)) {
      state.skippedBinaryOrInvalid += 1;
      continue;
    }
    if (
      localHeaderOffset + 30 > zipBuffer.length ||
      zipBuffer.readUInt32LE(localHeaderOffset) !== 0x04034b50
    ) {
      state.skippedBinaryOrInvalid += 1;
      continue;
    }
    const lfhNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > zipBuffer.length) {
      state.skippedBinaryOrInvalid += 1;
      continue;
    }
    processZipEntryPayload(
      state,
      entryName,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      zipBuffer.subarray(dataStart, dataEnd)
    );
  }
}

function extractViaLocalFileHeaders(zipBuffer: Buffer, state: ZipExtractionState): void {
  let offset = 0;
  while (offset + 30 <= zipBuffer.length) {
    if (zipBuffer.readUInt32LE(offset) !== 0x04034b50) break;
    state.processedEntries += 1;
    if (state.processedEntries > MAX_ZIP_ENTRIES) {
      throw new Error(
        `ZIP_BOMB_BLOCKED: Quantidade de entradas ZIP excedeu o limite máximo (${MAX_ZIP_ENTRIES}).`
      );
    }
    const compressionMethod = zipBuffer.readUInt16LE(offset + 8);
    const compressedSize = zipBuffer.readUInt32LE(offset + 18);
    const uncompressedSize = zipBuffer.readUInt32LE(offset + 22);
    const nameLen = zipBuffer.readUInt16LE(offset + 26);
    const extraLen = zipBuffer.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLen + extraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > zipBuffer.length) break;
    const entryName = zipBuffer.subarray(nameStart, nameStart + nameLen).toString('utf8');
    offset = dataEnd;

    if (!entryName || entryName.endsWith('/')) continue;
    assertSafeZipEntryName(entryName);
    assertSafeCompressionRatio(entryName, compressedSize, uncompressedSize);

    if (shouldSkipOversizedEntry(entryName, compressionMethod, compressedSize, uncompressedSize)) {
      state.skippedBinaryOrInvalid += 1;
      continue;
    }
    processZipEntryPayload(
      state,
      entryName,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      zipBuffer.subarray(dataStart, dataEnd)
    );
  }
}

/**
 * Extrai entradas textuais de um buffer ZIP com proteção estrita contra:
 * - ZIP Slip / Path Traversal / Symlinks (ZIP_PATH_TRAVERSAL_BLOCKED)
 * - ZIP Bomb por excesso de entradas (> 2000), tamanho individual (> 2MB),
 *   volume cumulativo (> 64MB) ou taxa de compressão anômala (>= 100x para >= 1KB) (ZIP_BOMB_BLOCKED)
 */
export function extractZipBufferToFilesMap(zipBuffer: Buffer): ZipExtractionResult {
  const state: ZipExtractionState = {
    rawExtracted: {},
    skippedBinaryOrInvalid: 0,
    processedEntries: 0,
    totalUncompressedBytes: 0,
  };

  let eocdOffset = -1;
  const minEocdSearch = Math.max(0, zipBuffer.length - 65557);
  for (let i = zipBuffer.length - 22; i >= minEocdSearch; i--) {
    if (zipBuffer.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset >= 0) {
    extractViaCentralDirectory(zipBuffer, eocdOffset, state);
  } else {
    extractViaLocalFileHeaders(zipBuffer, state);
  }

  const { sanitizedMap, skippedFiles } = sanitizeUploadedFilesMap(state.rawExtracted);
  return {
    filesMap: sanitizedMap,
    skippedCount: state.skippedBinaryOrInvalid + skippedFiles.length,
  };
}
