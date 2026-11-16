/**
 * 最小 QR 码编码器（字节模式，纠错等级 M，版本 1–9）。
 *
 * 为什么自己写：插件要保持零依赖。DSH 宿主里没有保证可用的二维码库，
 * 而「扫码打开」这个体验又必须有二维码。所以这里实现一个够用的子集：
 *   - 字节模式（UTF-8 原样放进去，扫码 App 按 UTF-8 解）
 *   - 纠错等级 M（能容忍约 15% 污损，手机屏幕反光也扫得出）
 *   - 版本 1–9（最多 182 字节，装得下 otpauth 链接和隧道 URL）
 *   - 8 种掩码按标准罚分挑最优
 *
 * 正确性靠对照验证：同参数下与成熟实现（npm 的 qrcode 包）逐模块比对。
 */

/** 每个版本在纠错等级 M 下的 [总码字数, 每块纠错码字数, 块数]。 */
const VERSIONS_M = {
  1: [26, 10, 1],
  2: [44, 16, 1],
  3: [70, 26, 1],
  4: [100, 18, 2],
  5: [134, 24, 2],
  6: [172, 16, 4],
  7: [196, 18, 4],
  8: [242, 22, 4],
  9: [292, 22, 5],
};

/** 对齐图形中心坐标。 */
const ALIGNMENT = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
};

/** 纠错等级 M 的格式信息两位编码是 00。 */
const ECC_BITS_M = 0;

function dataCodewords(version) {
  const [total, ec, blocks] = VERSIONS_M[version];
  return total - ec * blocks;
}

/** 字节模式能塞多少字节（扣掉模式指示符 4 位与字符计数 8 位）。 */
export function byteCapacity(version) {
  return dataCodewords(version) - 2;
}

/** 选能装下的最小版本；装不下抛错（交给调用方截短或报错）。 */
export function pickVersion(bytes) {
  for (let v = 1; v <= 9; v += 1) {
    if (byteCapacity(v) >= bytes) return v;
  }
  throw new Error(`内容太长，QR 放不下（${bytes} 字节，上限 ${byteCapacity(9)}）`);
}

// ── GF(256) 上的多项式运算，用于 Reed–Solomon 纠错 ──────────────────────────
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d; // 本原多项式 x^8+x^4+x^3+x^2+1
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

/** 生成多项式 (x - a^0)(x - a^1)...(x - a^(degree-1))。 */
function generatorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

/** 对一块数据算纠错码字。 */
function rsRemainder(data, degree) {
  const gen = generatorPoly(degree);
  const result = new Uint8Array(degree);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.copyWithin(0, 1);
    result[degree - 1] = 0;
    for (let i = 0; i < degree; i += 1) {
      result[i] ^= gfMul(gen[i + 1], factor);
    }
  }
  return result;
}

// ── 位流 ──────────────────────────────────────────────────────────────────
function buildCodewords(bytes, version) {
  const totalData = dataCodewords(version);
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4);                        // 字节模式
  push(bytes.length, version < 10 ? 8 : 16);
  for (const byte of bytes) push(byte, 8);

  const capacityBits = totalData * 8;
  // 终止符：最多 4 个 0
  push(0, Math.min(4, capacityBits - bits.length));
  // 补到字节边界
  while (bits.length % 8 !== 0) bits.push(0);

  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | bits[i + j];
    data.push(byte);
  }
  // 填充码字：0xEC / 0x11 交替
  let pad = 0;
  while (data.length < totalData) {
    data.push(pad % 2 === 0 ? 0xec : 0x11);
    pad += 1;
  }

  // 分块 + 纠错 + 交织
  const [, ecPerBlock, blockCount] = VERSIONS_M[version];
  const perBlock = Math.floor(totalData / blockCount);
  const extra = totalData % blockCount;
  const blocks = [];
  let offset = 0;
  for (let i = 0; i < blockCount; i += 1) {
    const size = perBlock + (i >= blockCount - extra ? 1 : 0);
    const chunk = data.slice(offset, offset + size);
    offset += size;
    blocks.push({ data: chunk, ec: rsRemainder(chunk, ecPerBlock) });
  }

  const out = [];
  const maxData = Math.max(...blocks.map((b) => b.data.length));
  for (let i = 0; i < maxData; i += 1) {
    for (const block of blocks) {
      if (i < block.data.length) out.push(block.data[i]);
    }
  }
  for (let i = 0; i < ecPerBlock; i += 1) {
    for (const block of blocks) out.push(block.ec[i]);
  }
  return out;
}

// ── 矩阵 ──────────────────────────────────────────────────────────────────
function createMatrix(size) {
  return {
    size,
    modules: Array.from({ length: size }, () => new Array(size).fill(false)),
    reserved: Array.from({ length: size }, () => new Array(size).fill(false)),
  };
}

function placeFinder(m, row, col) {
  for (let r = -1; r <= 7; r += 1) {
    for (let c = -1; c <= 7; c += 1) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || rr >= m.size || cc < 0 || cc >= m.size) continue;
      const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6))
        || (c >= 0 && c <= 6 && (r === 0 || r === 6))
        || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
      m.modules[rr][cc] = inRing;
      m.reserved[rr][cc] = true;
    }
  }
}

function placeAlignment(m, version) {
  const centers = ALIGNMENT[version];
  for (const row of centers) {
    for (const col of centers) {
      // 与定位图形重叠的位置跳过
      if ((row === 6 && col === 6) || (row === 6 && col === m.size - 7) || (row === m.size - 7 && col === 6)) continue;
      for (let r = -2; r <= 2; r += 1) {
        for (let c = -2; c <= 2; c += 1) {
          const on = Math.max(Math.abs(r), Math.abs(c)) !== 1;
          m.modules[row + r][col + c] = on;
          m.reserved[row + r][col + c] = true;
        }
      }
    }
  }
}

function placeTiming(m) {
  for (let i = 8; i < m.size - 8; i += 1) {
    const on = i % 2 === 0;
    if (!m.reserved[6][i]) { m.modules[6][i] = on; m.reserved[6][i] = true; }
    if (!m.reserved[i][6]) { m.modules[i][6] = on; m.reserved[i][6] = true; }
  }
}

function reserveFormatAreas(m) {
  const size = m.size;
  for (let i = 0; i < 9; i += 1) {
    if (!m.reserved[8][i]) m.reserved[8][i] = true;
    if (!m.reserved[i][8]) m.reserved[i][8] = true;
  }
  for (let i = 0; i < 8; i += 1) {
    m.reserved[8][size - 1 - i] = true;
    m.reserved[size - 1 - i][8] = true;
  }
  // 固定的深色模块
  m.modules[size - 8][8] = true;
  m.reserved[size - 8][8] = true;
}

/** 15 位格式信息：ECC 2 位 + 掩码 3 位，经 BCH(15,5) 编码后异或 0x5412。 */
function formatBits(mask) {
  let data = (ECC_BITS_M << 3) | mask;
  let value = data << 10;
  for (let i = 4; i >= 0; i -= 1) {
    if ((value >>> (i + 10)) & 1) value ^= 0x537 << i;
  }
  return ((data << 10) | value) ^ 0x5412;
}

/**
 * 写两份格式信息（15 位，两份互为副本）。
 *
 * 位置按标准走，不能用「行列对称」想当然：第一份**竖着写在矩阵的 (行, 第 8 列)**，
 * 第二份**横着写在 (第 8 行, 列)**。写反了数据区会一字不差、只有格式区错位，
 * 扫码器读到的掩码与纠错等级就是错的，整张图直接作废——这个坑实测踩过，
 * 差异正好只出现在 (i,8) 与 (8,i) 这两组对称位置上。
 */
function placeFormat(m, mask) {
  const bits = formatBits(mask);
  const n = m.size;
  const bit = (i) => ((bits >>> i) & 1) === 1;

  // 第一份：环绕左上角定位图形
  for (let i = 0; i < 15; i += 1) {
    const row = i < 6 ? i : i < 8 ? i + 1 : n - 15 + i;
    m.modules[row][8] = bit(i);
    m.reserved[row][8] = true;
  }

  // 第二份：右上角横排 + 左下角竖排
  for (let i = 0; i < 15; i += 1) {
    const col = i < 8 ? n - 1 - i : i === 8 ? 7 : 14 - i;
    m.modules[8][col] = bit(i);
    m.reserved[8][col] = true;
  }

  // 固定的深色模块
  m.modules[n - 8][8] = true;
  m.reserved[n - 8][8] = true;
}

/** 版本信息（版本 7 起才有），18 位 BCH(18,6)。 */
function placeVersion(m, version) {
  if (version < 7) return;
  let value = version << 12;
  for (let i = 5; i >= 0; i -= 1) {
    if ((value >>> (i + 12)) & 1) value ^= 0x1f25 << i;
  }
  const bits = (version << 12) | value;
  const size = m.size;
  for (let i = 0; i < 18; i += 1) {
    const on = ((bits >>> i) & 1) === 1;
    const a = Math.floor(i / 3);
    const b = i % 3;
    m.modules[a][size - 11 + b] = on;
    m.reserved[a][size - 11 + b] = true;
    m.modules[size - 11 + b][a] = on;
    m.reserved[size - 11 + b][a] = true;
  }
}

/** 按标准顺序把码字铺进矩阵（两列一组，从右下角往上走，遇列 6 跳过）。 */
function placeData(m, codewords) {
  let bitIndex = 0;
  const total = codewords.length * 8;
  let upward = true;
  for (let right = m.size - 1; right > 0; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < m.size; step += 1) {
      const row = upward ? m.size - 1 - step : step;
      for (let c = 0; c < 2; c += 1) {
        const col = right - c;
        if (m.reserved[row][col]) continue;
        const on = bitIndex < total ? ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) === 1 : false;
        m.modules[row][col] = on;
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function applyMask(m, mask) {
  const test = MASKS[mask];
  for (let r = 0; r < m.size; r += 1) {
    for (let c = 0; c < m.size; c += 1) {
      if (m.reserved[r][c]) continue;
      if (test(r, c)) m.modules[r][c] = !m.modules[r][c];
    }
  }
}

/** 标准四条罚分：连续同色、2×2 同色块、类定位图形、深浅比例。 */
function penalty(m) {
  const size = m.size;
  let score = 0;
  const line = (get) => {
    for (let i = 0; i < size; i += 1) {
      let run = 1;
      for (let j = 1; j < size; j += 1) {
        if (get(i, j) === get(i, j - 1)) run += 1;
        else { if (run >= 5) score += run - 2; run = 1; }
      }
      if (run >= 5) score += run - 2;
    }
  };
  line((r, c) => m.modules[r][c]);
  line((r, c) => m.modules[c][r]);
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = m.modules[r][c];
      if (v === m.modules[r][c + 1] && v === m.modules[r + 1][c] && v === m.modules[r + 1][c + 1]) score += 3;
    }
  }
  const pattern = [true, false, true, true, true, false, true];
  const matches = (get, i, j) => {
    for (let k = 0; k < 7; k += 1) if (get(i, j + k) !== pattern[k]) return false;
    const before = j >= 4 && !get(i, j - 1) && !get(i, j - 2) && !get(i, j - 3) && !get(i, j - 4);
    const after = j + 11 <= size && !get(i, j + 7) && !get(i, j + 8) && !get(i, j + 9) && !get(i, j + 10);
    return before || after;
  };
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c + 7 <= size; c += 1) {
      if (matches((i, j) => m.modules[i][j], r, c)) score += 40;
      if (matches((i, j) => m.modules[j][i], r, c)) score += 40;
    }
  }
  let dark = 0;
  for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) if (m.modules[r][c]) dark += 1;
  const ratio = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(ratio - 50) / 5) * 10;
  return score;
}

/**
 * 把文本编成 QR 矩阵。
 * @param {string} text 内容（按 UTF-8 编码）
 * @param {{mask?: number}} [options] `mask` 仅供测试强制指定掩码
 * @returns {{size:number, modules:boolean[][], version:number, mask:number}}
 */
export function encode(text, options = {}) {
  const bytes = [...new TextEncoder().encode(text)];
  const version = pickVersion(bytes.length);
  const codewords = buildCodewords(bytes, version);
  const size = 17 + version * 4;

  const build = (mask) => {
    const m = createMatrix(size);
    placeFinder(m, 0, 0);
    placeFinder(m, 0, size - 7);
    placeFinder(m, size - 7, 0);
    placeAlignment(m, version);
    placeTiming(m);
    reserveFormatAreas(m);
    placeVersion(m, version);
    placeData(m, codewords);
    applyMask(m, mask);
    placeFormat(m, mask);
    return m;
  };

  const forced = Number.isInteger(options.mask) ? options.mask : null;
  if (forced !== null) {
    const m = build(forced);
    return { size, modules: m.modules, version, mask: forced };
  }

  let best = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = build(mask);
    const score = penalty(candidate);
    if (score < bestScore) { best = candidate; bestScore = score; best.mask = mask; }
  }
  return { size, modules: best.modules, version, mask: best.mask };
}

/** 渲成 SVG 路径（给网页用，缩放不失真）。 */
export function toSvg(text, { scale = 6, margin = 2, dark = '#151517', light = '#ffffff' } = {}) {
  const { size, modules } = encode(text);
  const dim = (size + margin * 2) * scale;
  const parts = [];
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (!modules[r][c]) continue;
      parts.push(`M${(c + margin) * scale} ${(r + margin) * scale}h${scale}v${scale}h-${scale}z`);
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${dim}" height="${dim}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges">`
    + `<rect width="${dim}" height="${dim}" fill="${light}"/>`
    + `<path d="${parts.join('')}" fill="${dark}"/>`
    + '</svg>';
}
