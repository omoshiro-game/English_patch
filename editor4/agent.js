// agent.js — Frida 17+ compatible
'use strict';
//# sourceURL=agent.js

// -----------------------------
// Helpers (Frida 17 migration)
// -----------------------------

function waitForModule(name, timeoutMs = 3000, stepMs = 50) {
  const t0 = Date.now();
  while (!Process.findModuleByName(name)) {
    if (Date.now() - t0 > timeoutMs) throw new Error(`Timeout waiting for ${name}`);
    Thread.sleep(stepMs / 1000);
  }
}

function getExportPtr(modName, name) {
  const m = Process.findModuleByName(modName);
  if (!m) return null;
  // Frida 17: use instance method
  return m.findExportByName(name);
}

function resolveWinApi(name) {
  // Prefer KernelBase (forwarder target), then Kernel32, then global
  return (
    getExportPtr('KernelBase.dll', name) ||
    getExportPtr('kernel32.dll', name) ||
    Module.getGlobalExportByName(name) // throws if missing
  );
}

// Convenience
// const NULL = ptr(0);

// -----------------------------
// Win32 conversion functions
// -----------------------------
// Frida 17: use Process.getModuleByName(...).getExportByName(...)
waitForModule('KernelBase.dll', 3000);
waitForModule('kernel32.dll', 3000);

const mb2wcPtr = resolveWinApi('MultiByteToWideChar');
const wc2mbPtr = resolveWinApi('WideCharToMultiByte');

const mb2wc = new NativeFunction(
  mb2wcPtr,
  'int',
  ['uint','uint','pointer','int','pointer','int']
);
const wc2mb = new NativeFunction(
  wc2mbPtr,
  'int',
  ['uint','uint','pointer','int','pointer','int','pointer','pointer']
);

// -----------------------------
// String helpers
// -----------------------------
function readAnsiString(p) {
  if (p.isNull()) return null;
  try {
    return p.readUtf8String(); // may work if actually UTF-8
  } catch (_) {
    try { return p.readAnsiString(); } catch (_2) { return '[invalid ANSI string]'; }
  }
}

function readWideString(p) {
  if (p.isNull()) return null;
  try {
    return p.readUtf16String();
  } catch (_) {
    return '[invalid wide string]';
  }
}

// Null-terminated ANSI length
function getAnsiByteLength(p) {
  let len = 0;
  for (;;) {
    const b = p.add(len).readU8(); // Frida 17 style
    if (b === 0) break;
    len++;
  }
  return len;
}

// Write padded/truncated ASCII (fits ANSI/SJIS byte=char)
function writePaddedAnsiString(p, originalByteLength, newText) {
  const newLen = newText.length;
  if (newLen <= originalByteLength) {
    const padded = newText + ' '.repeat(originalByteLength - newLen);
    p.writeAnsiString(padded);
  } else {
    p.writeAnsiString(newText.substring(0, originalByteLength));
  }
  p.add(originalByteLength).writeU8(0); // ensure NUL
}

// Quick ASCII check
function isAscii(str) {
  return /^[\x00-\x7F]*$/.test(str);
}

// -----------------------------
// SJIS <-> UTF-8 converters
// -----------------------------
function sjisPtrToUtf8(ptrAnsi) {
  if (ptrAnsi.isNull()) return null;
  const CP_SJIS = 932, CP_UTF8 = 65001, MB_ERR_INVALID_CHARS = 0;

  // SJIS -> UTF-16 (size)
  let wcCount = mb2wc(CP_SJIS, MB_ERR_INVALID_CHARS, ptrAnsi, -1, NULL, 0);
  if (wcCount <= 0) return null;

  // SJIS -> UTF-16 (convert)
  const wideBuf = Memory.alloc(wcCount * 2);
  mb2wc(CP_SJIS, MB_ERR_INVALID_CHARS, ptrAnsi, -1, wideBuf, wcCount);

  // UTF-16 -> UTF-8 (size)
  let utf8Count = wc2mb(CP_UTF8, 0, wideBuf, -1, NULL, 0, NULL, NULL);
  if (utf8Count <= 0) return null;

  // UTF-16 -> UTF-8 (convert)
  const utf8Buf = Memory.alloc(utf8Count);
  wc2mb(CP_UTF8, 0, wideBuf, -1, utf8Buf, utf8Count, NULL, NULL);

  // Exclude trailing NUL
  return utf8Buf.readUtf8String(utf8Count - 1);
}

function utf8ToSjis(utf8Str) {
  if (!utf8Str) return null;
  const CP_UTF8 = 65001, CP_SJIS = 932;

  const utf8Ptr = Memory.allocUtf8String(utf8Str);

  // UTF-8 -> UTF-16 (size)
  let wcCount = mb2wc(CP_UTF8, 0, utf8Ptr, -1, NULL, 0);
  if (wcCount <= 0) return null;

  const wideBuf = Memory.alloc(wcCount * 2);
  mb2wc(CP_UTF8, 0, utf8Ptr, -1, wideBuf, wcCount);

  // UTF-16 -> SJIS (size)
  let sjisCount = wc2mb(CP_SJIS, 0, wideBuf, -1, NULL, 0, NULL, NULL);
  if (sjisCount <= 0) return null;

  const sjisBuf = Memory.alloc(sjisCount);
  wc2mb(CP_SJIS, 0, wideBuf, -1, sjisBuf, sjisCount, NULL, NULL);

  return sjisBuf; // pointer to SJIS bytes
}

// -----------------------------
// TRANSLATIONS (unchanged)
// -----------------------------
// Paste your existing huge TRANSLATIONS object here:
/*
Common abbreviations:
- dmg = damage
- pwr = power
- str = strength
- atk = attack
- char = character
- L/R = left/right
- U/D = up/down
- cmd = command
- bmp = bitmap
- exec = execute/execution  
- char = character
- invinc = invincible
- insta = instant
- thru = through
- pre- = before
- L/R = left/right
- U/D = up/down
 */
const TRANSLATIONS = {
  '全ての条件が真なら成立': 'if all true',
  '1つ以上の条件が真なら成立': 'if any true', 
  '継承しない': 'no inherit',
  'コモンパレット': 'common palette',
  'ステージパレット': 'stage palette',
  'プレイヤー': 'player',
  'コンピューター': 'computer',
  '常時': 'alws',
  'ダメージを受けた時（設定値「威力」が0以外）': 'dmg taken (pwr != 0)',
  'ダメージを受けた時（受けたダメージが1以上）': 'dmg taken (>=1)',
  '衝撃を受けた時（設定値「衝撃」が0以外）': 'shock taken (str != 0)',
  '衝撃を受けた時（受けた衝撃が1以上か-1以下）': 'shock taken (>=1 or <=-1)',
  '死亡した時': 'on death',
  'キャラに当たった時': 'hit char',
  'ブロックキャラに当たった時': 'hit block char',
  'ブロックキャラに乗っている時': 'riding block',
  'ショットに当たった時': 'hit shot',
  'アイテムに当たった時': 'hit item',
  'ブロックに当たった時': 'hit block',
  '自分の左右にブロックが当たった時': 'block hit L/R',
  '自分の左にブロックが当たった時': 'block hit left',
  '自分の右にブロックが当たった時': 'block hit right',
  '自分の上下にブロックが当たった時': 'block hit U/D',
  '自分の上にブロックが当たった時': 'block hit up',
  '自分の下にブロックが当たった時': 'block hit down',
  '主人公に乗られている時': 'hero riding',
  'キャラに乗られている時': 'char riding',
  'アタックでダメージを与えた時（設定値「威力」が0以外）': 'atk dmg (pwr != 0)',
  'アタックでダメージを与えた時（与えたダメージが1以上）': 'atk dmg (>=1)',
  'アタックで衝撃を与えた時（設定値「衝撃」が0以外）': 'atk shock (str != 0)',
  'アタックで衝撃を与えた時（与えた衝撃が1以上か-1以下）': 'atk shock (>=1 or <=-1)',
  'アタックを当てた時': 'atk hit',
  'ステージ開始前': 'pre-stage',
  'なし（フローの操作コマンドで実行）': 'none (flow cmd)',
  'ターゲット1': 'target 1',
  'ターゲット2': 'target 2',
  'ターゲット3': 'target 3',
  'ターゲット4': 'target 4',

  '01 主人公(専用bmp)': '01 hero(cbmp)',
  '02 敵': '02 en',
  '03 スピルト(×9)': '03 sp(x9)',
  'なし': 'no',
  '001 主人公死亡5': '001 hd5',
  '002 敵死亡5': '002 ed5', 
  '003 無敵終了前20': '003 pi20',
  'ブロック': 'Block',
  'キャラ': 'Char',
  'アイテム': 'Item',
  'ショット': 'Shot',
  '専用bmp': 'cst_bmp',
  '通常実行': 'norm',
  '反転実行': 'rev',
  '往復実行': 'rtrip',
  '表示しない': 'hide',
  '表示する': 'show',
  'エディターでのみ表示': 'ed only',
  'ON (ブロックをすり抜ける)': 'ON(pass blk)',
  'ON (ブロックに当たる)': 'ON(hit blk)',
  'ON (ブロックに当たると即死)': 'ON(insta blk)',
  'ON (ショットが当たる)': 'ON(S hit)',
  'ON (ショットがすり抜ける)': 'ON(S pass)',
  '白': 'Wh',
  '黒': 'Bk',
  '赤': 'Rd',
  '緑': 'Gr',
  '藍': 'Bu',
  '黄': 'Yl',
  '赤紫': 'Prpl',
  '青紫': 'Cyan',
  '4色': '4cl',
  'しない': 'no',
  '×4': 'x4',
  '×9': 'x9',
  '×16': 'x16',
  '×25': 'x25',
  '×36': 'x36',
  '×49': 'x49',
  '×64': 'x64',
  '×81': 'x81',
  '×100': 'x100', 
  '画面内全て': 'all scr',
  'キャラを中心とした円形': 'C circle',
  'キャラの前方に円形': 'C front circ',
  'キャラを中心とした正方形': 'C square',
  'キャラの前方に正方形': 'C front sq',

  'フドー': 'Fudo',
  'キャラ対キャラの当たり判定範囲（推奨）': 'Char-Char Hit Range(rec)',
  'キャラ対ショットの当たり判定範囲': 'Char-Shot Hit Range',
  'ショット対キャラの当たり判定範囲': 'Shot-Char Hit Range',
  '32×32': '32x32',
  '画面内': 'OnScr',
  'X座標のみ画面内': 'X On Screen',
  'Y座標のみ画面内': 'Y On Screen',
  '全範囲': 'AllRng',
  '範囲かグループが真なら成立': 'If Range/Group True',
  '一度範囲かグループが真になると、以後無条件で成立': 'Once Range/Group True',
  '範囲とグループが偽なら成立': 'If Range&Group False',
  'コモン変数条件': 'ComVarCond',
  'ステージ変数条件': 'Stage Var Cond',
  'キャラ変数条件': 'Char Var Cond',
  'ステータス条件': 'Status Cond',
  'ステータス条件2': 'Status Cond2',
  'ステータス条件3': 'Status Cond3',
  '距離条件': 'DistCond',
  '押': 'Pr',
  '離': 'Rl',
  '全てのキーが真なら成立': 'If All Keys True',
  '1つ以上のキーが真なら成立': 'If Any Key True',
  '1つだけキーが真なら成立': 'If One Key True',
  'ウエイト': 'Wait',
  '直線移動': 'LineMove',
  '地上折り返し移動': 'GroundRetMove',
  '円移動': 'CrcMov',
  '突撃移動': 'ChrgMov',
  '誘導移動': 'GuideMov',
  '画面外回避移動': 'AvoidOffscr',
  '移動の無効化': 'Disable Move',
  '向き変更': 'ChngDir',
  'ジャンプ': 'Jump',
  'ショット': 'Shot',
  'ソード': 'Sword',
  'ブロック召喚': 'Block Summon',
  'キャラ召喚': 'Char Sum.',
  'アイテム召喚': 'Item Sum.',
  'フローの操作': 'Flow Control',
  'ステージクリア': 'Stage Clear',
  'ゲームウエイト': 'Game Wait',
  'メッセージ': 'Message',
  'ワープ': 'Warp',
  'ターゲットの設定': 'Set Target',
  'ステータスの操作': 'Status Control',
  'ステータスの操作2': 'Status Control2',
  '消滅': 'Vnsh',
  'アイテムの取得': 'Get Item',
  'グラフィックの変更': 'Change Graphic',
  '基本アニメセットの変更': 'Change Base Anim',
  'アニメの実行': 'Exec Anim',
  'エフェクトの実行': 'Exec Effect',
  'キャラエフェクトの実行': 'Exec Char Effect',
  '画面エフェクトの実行': 'Exec Screen Effect',
  'ピクチャーの表示': 'Show Picture',
  '画面の色を変更': 'ChgScrColor',
  '背景の変更': 'Change BG',
  '効果音の再生': 'Play SE',
  'BGMの再生': 'Play BGM',
  'コードの実行': 'Exec Code',
  'アレンジ': 'Arrange',
  'ループ': 'Loop',
  // --------------------------------------------------------------------------

  '自分': 'Self',
  'このフロー': 'This Flow',
  'このフロー以外全て': 'All Other Flows',
  '指定IDのフロー': 'Flow By ID',
  '開始': 'Strt',
  '終了': 'End',
  '一時停止': 'Pause',
  '再開': 'Resm',
  '削除': 'Del',
  '永久停止': 'StopPerm',
  '001 振動（横）10': '001 Vib(H)10',
  '時間と速度を指定': 'Time+Speed',
  '時間と距離を指定': 'Time+Dist',
  '速度と距離を指定': 'Speed+Dist',
  '方向で指定': 'By Dir',
  '目標座標で指定': 'By Target Pos',
  '前': 'Fw',
  '後': 'Bk',
  '左': 'Lf',
  '右': 'Rg',
  '前Y': 'FwY',
  '後Y': 'BkY',
  '上': 'Up',
  '下': 'Dw',
  '左上': 'UpLf',
  '左下': 'DwLf',
  '右上': 'UpRg',
  '右下': 'DwRg',
  '入力方向': 'InputDir',
  '配置位置からの相対座標': 'Rel From Place',
  '相対座標': 'Rel Pos',
  '絶対座標': 'Abs Pos',
  '画面座標': 'Scr Pos',
  '(bl)で指定': 'By bl',
  '(dot)で指定': 'By dot',
  '(hbl)で指定': 'By hbl',
  '移動アニメ': 'Move Anim',
  '静止アニメ': 'Idle Anim',
  'その他': 'Other',
  'なし（変更しない）': 'No Change',
  '01 アクション（予備動作有）': '01 Act(Prep)',
  '02 アクション（予備動作無）': '02 Act(NoPrep)',
  '03 剣－斬り': '03 SwrdSlsh',
  '04 剣－突き': '04 SwrdThrs',
  '05 スキル（主人公）': '05 Skill(Hero)',
  '06 スキル上（主人公）': '06 SkillUp(Hero)',
  '07 スキル下（主人公）': '07 SkillDown(Hero)',
  '08 コマ2': '08 Cmd2',
  '09 コマ3': '09 Cmd3',
  '次のステージへ': 'Next Stage',
  '番号で指定': 'By Number',
  'パスで指定': 'By Path',
  'ワールドクリア': 'World Clear',
  '左向き': 'FaceLf',
  '右向き': 'FaceRg',
  'ステージクリア時の向きと同じ': 'As Stage Clear',
  'ピクチャーの消去(ID非設定なら全消去)': 'Clear Pic(ID=All)',
  '001 ゲームクリア': '001 Game Clear',
  '画面中央に表示': 'Screen Center',
  'キャラの中心に表示': 'Char Center',
  '主人公の中心に表示': 'Hero Center',
  '画面座標で指定（左上を指定）': 'Scr Pos(TL)',
  '画面座標で指定（中心を指定）': 'Scr Pos(Center)',
  'ステージ座標で指定（左上を指定）': 'Stage Pos(TL)',
  'ステージ座標で指定（中心を指定）': 'Stage Pos(Center)',
  '進行キーが押されるまで表示': 'Until Key Press',
  'ステージ終了まで表示': 'Until Stage End',
  '時間で指定': 'By Time',
  '時間を指定': 'Set Time',
  '速度を指定': 'Set Speed',
  '右回り': 'ClckWs',
  '左回り': 'CCWs',
  '左向きなら右回り、右向きなら左回り': 'L=CW R=CCW',
  '左向きなら左回り、右向きなら右回り': 'L=CCW R=CW',
  '自分の上に表示': 'Above Self',
  '自分の下に表示': 'Below Self',
  '自分の中心に表示': 'Self Center',
  '主人公の上に表示': 'Above Hero',
  '主人公の下に表示': 'Below Hero',
  '主人公の中心に表示': 'Hero Center',
  '501 連打ダッシュ': '501 Rapid Dash',
  '502 緊急回避用': '502 Emergency',
  '503 連打ソード関係': '503 Rapid Sword',
  '504 連打ソード関係': '504 Rapid Sword',
  '505 連打ソード関係': '505 Rapid Sword',
  '506 状態異常：吸魔': '506 Status:Drain',
  '507 状態異常表示：吸魔': '507 Show:Drain',
  '508 吸魔用処理': '508 Drain Proc',
  '509 状態異常：絶好調': '509 Status:Peak',
  '510 状態異常表示：絶好調': '510 Show:Peak',
  '511 アローエリア右': '511 ArrowArea R',
  '512 アローエリア左': '512 ArrowArea L',
  '513 巻き込みコンボ数': '513 Combo Count',
  '514 交代システム': '514 Switch Sys',
  '515 変数取得君2個配置': '515 GetVar x2',
  '516 獲得ジェム補正': '516 Gem Bonus',
  '517 WoY用判定': '517 WoY Check',
  '518 演出用タイムカウンタ': '518 Effect Timer',
  '519 コンボシステム使っている': '519 Combo Sys On',
  '520 総合スコア': '520 Total Score',
  // ... continuing with similar compact patterns for all the numbered variables
  
  '表示': 'Show',
  '非表示': 'Hide',
  '反転(表示⇔非表示)': 'Toggle Show',
  '主人公': 'Hero',
  '最も近いキャラ': 'Nearest Char',
  'キャラ（キャラIDで指定）': 'Char(By ID)',
  '親キャラ（自分を召喚したキャラ）': 'Parent Char',
  '子キャラ（最後に召喚したキャラ）': 'Child Char',
  '子キャラ（条件付き。後で召喚したキャラ優先)': 'Child Char(Cond)',
  '全範囲（画面内のキャラ優先）': 'All Range(Scr)',
  '1 キャラ変数-1': '1 CharVar-1',
  '2 キャラ変数-2': '2 CharVar-2',
  '3 キャラ変数-3': '3 CharVar-3',
  '4 キャラ変数-4': '4 CharVar-4',
  '5 キャラ変数-5': '5 CharVar-5',
  '6 キャラ変数-6': '6 CharVar-6',
  '7 キャラ変数-7': '7 CharVar-7',
  '8 キャラ変数-8': '8 CharVar-8',
  'である': 'Is',
  'でない': 'Is Not',
  '以上': '>=',
  '以下': '<=',
  'より上': '>',
  'より下': '<',
  'の倍数である': 'Multiple Of',
  'の倍数でない': 'Not Multiple',
  'ターゲット無し': 'No Target',
  'ターゲットを変更しない': 'Keep Target',
  'BGMの停止': 'Stop BGM',
  'ステータス': 'Status',
  '変数': 'Var',
  'フロー変数': 'Flow Var',
  'システム': 'System',
  'キャラ変数': 'Char Var',
  '最大HP': 'Max HP',
  '最大SP': 'Max SP',
  'キャラID': 'Char ID',
  'X座標': 'X Crd',
  'Y座標': 'Y Crd',
  'Z座標': 'Z Crd',
  'マーク番号': 'Mark No',
  '視界範囲(hbl)': 'Sight(hbl)',
  '体当たりの威力': 'Body Atk Pwr',
  '体当たりの衝撃': 'Body Atk Str',
  '防御力': 'Defn',
  '衝撃耐性': 'ShckRes',
  '止まりやすさ': 'Stop Ease',
  '倒したら獲得するスコア': 'Kill Score',
  'コモン変数': 'Common Var',
  'ステージ変数': 'Stage Var',
  '1 フロー変数A': '1 FlowVar A',
  '2 フロー変数B': '2 FlowVar B',
  '＝': '=',
  '＋': '+',
  '－': '-',
  '×': 'x',
  '÷': '÷',
  '÷ X の余り': 'Remainder',
  'X ％': 'X %',
  '定数': 'Cnst',
  '乱数': 'Rand',
  '通常の計算': 'NormCalc',
  '最大値に対する％で指定': 'By Max %',
  '現在値に対する％で指定': 'By Current %',
  'キャラの中心': 'Char Center',
  'キャラの中央下': 'Char Bottom',
  '歩行なら中央下、飛行なら中心': 'Walk=Bot Fly=Ctr',
  '目標X': 'TrgtX',
  '目標X(dot)': 'Target X(dot)',
  '目標Y': 'TrgtY',
  '目標Y(dot)': 'Target Y(dot)',
  '角度': 'Angl',
  '分身値による増加角度': 'Clone Angle+',
  '透明': 'Invs',
  '向き固定': 'Dir Lock',
  '飛行': 'Fly',
  '無敵': 'Invc',
  '巨大化': 'Giant',
  'オートスクロールとシンクロ': 'Sync Scroll',
  '左を向く': 'FaceLf',
  '右を向く': 'FaceRg',
  'ターゲット1がいる方を向く': 'Face Target1',
  'ターゲット1がいる方の逆を向く': 'Face Away T1',
  '最後にブロックが当たった方を向く': 'Face Block Hit',
  '最後にブロックが当たった方の逆を向く': 'Face Away Block',
  '01 ショットA': '01 Shot A',
  '02 ショットB': '02 Shot B',
  '03 ショットC': '03 Shot C',
  '04 レーザー': '04 Laser',
  '05 火A': '05 Fire A',
  '06 火B': '06 Fire B',
  '07 火C': '07 Fire C',
  '08 風A': '08 Wind A',
  '09 風B': '09 Wind B',
  '10 風C': '10 Wind C',
  '11 電撃A': '11 Elec A',
  '12 電撃B': '12 Elec B',
  '13 闇A': '13 Dark A',
  '14 闇B': '14 Dark B',
  '15 闇C': '15 Dark C',
  '16 光A': '16 Light A',
  '17 光B': '17 Light B',
  '18 水': '18 Water',
  '19 氷': '19 Ice',
  '20 銃A': '20 Gun A',
  '21 銃B': '21 Gun B',
  '22 銃C': '22 Gun C',
  '23 コミカルA': '23 Comic A',
  '24 コミカルB': '24 Comic B',
  '25 コミカルC': '25 Comic C',
  '26 ソード': '26 Sword',
  '27 ジャンプ': '27 Jump',
  '28 ジェムA': '28 Gem A',
  '29 ジェムB': '29 Gem B',
  '30 アップA': '30 Up A',
  '31 アップB': '31 Up B',
  '32 ダウンA': '32 Down A',
  '33 ダウンB': '33 Down B',
  '34 装備A': '34 Equip A',
  '35 装備B': '35 Equip B',
  '36 回復A': '36 Heal A',
  '37 回復B': '37 Heal B',
  '38 スイッチA': '38 Switch A',
  '39 スイッチB': '39 Switch B',
  '40 エラー': '40 Error',
  '子以下のキャラ': 'Child+ Chars',
  '子のショット': 'Child Shots',
  '子以下のキャラと子以下のショット': 'Child+ All',
  '子以下のキャラと孫以下のショット': 'Child+ Grand',
  '高さがキーで調節できない': 'No Key Height',
  '高さがキーで調節できる(主人公のみ有効)': 'Key Height(Hero)',
  '慣性移動速度に応じて高さを決定(主人公のみ有効)': 'Inert Height(Hero)',
  '間隔(hbl)': 'Interval(hbl)',
  '01 剣－斬り－前': '01 Sword-SlshF',
  '02 剣－突き－前': '02 Sword-ThrstF',
  'ブロックを召喚': 'Summon Block',
  'ブロックを消す': 'Remove Block',
  'ブロックがなければ召喚、ブロックがあれば消す': 'Toggle Block',
  '直進A': 'StrgA',
  '直進B': 'StrgB',
  '拡散': 'Sprd',
  '落雷': 'Thnd',
  '爆発': 'Expl',
  '包囲': 'Surr',
  'ターゲット': 'Target',
  '直進': 'Strg',
  '主人公を狙う': 'Aim Hero',
  '近いキャラを狙う': 'Aim Near Char',
  'ターゲットを狙う': 'Aim Target',
  '主人公へ誘導': 'Guide Hero',
  '近いキャラへ誘導（対象死亡時、誘導を無効化）': 'Guide Near(Off)',
  'ターゲットへ誘導': 'Guide Target',
  '近いキャラへ誘導（対象死亡時、対象を変更）': 'Guide Near(Chg)',
  'ウェーブ': 'Wave',
  '落下': 'Fall',
  '002 ノーマルブロック-赤': '002 Norm Blk-Red',
  '003 ノーマルブロック-緑': '003 Norm Blk-Grn',
  // ... continuing with block types using "Blk" abbreviation
  
  'パレットの設定に準ずる': 'Use Palette',
  '使用者と同じ': 'Same As User',
  '001 ヤシーユ（主人公）': '001 Yashiyu(Hero)',
  '002 フドー': '002 Fudo',
  '003 スズキ': '003 Suzuki',
  '004 タナカ': '004 Tanaka',
  '005 サトー': '005 Sato',
  '006 炎使い': '006 Fire User',
  '007 光使い': '007 Light User',
  '008 竜巻使い': '008 Tornado User',
  '009 雷使い': '009 Thnd Usr',
  '010 闇使い': '010 Dark User',
  '011 古の魔道士': '011 Ancient Mage',
  '012 伝説の魔道士': '012 Legend Mage',
  '013 ゴースト': '013 Ghost',
  '014 スライム': '014 Slime',
  '015 黒胡麻プリン': '015 Black Sesame',
  '016 赤炎': '016 Red Flm',
  '017 赤炎（無敵）': '017 Red Flame(Inv)',
  '018 青炎': '018 Blue Flm',
  '019 紫炎': '019 Prpl Flm',
  '020 黄炎': '020 Yelw Flm',
  '021 緑炎': '021 Green F',
  '022 さめ': '022 Shark',
  '023 くじら': '023 Whale',
  '024 スーパーくじら': '024 Super Whale',
  '025 こうもり': '025 Bat',
  '026 シャドーピープル': '026 Shadow People',
  '027 テールマン': '027 Tailman',
  '028 こんぺいとう': '028 Konpeito',
  '029 空飛ぶ缶詰': '029 Flying Can',
  '030 ロージン-LR': '030 Rojin-LR',
  '031 ロージン-UD': '031 Rojin-UD',
  '034 爆撃UFO': '034 Bomb UFO',
  '035 爆撃UFO改': '035 Bomb UFO+',
  '036 キャノン': '036 Cannon',
  '037 スーパーキャノン': '037 Super Cannon',
  '038 地獄の使い': '038 Hell Messenger',
  '039 ロボ': '039 Robo',
  '040 ガンマン': '040 Gunman',
  '041 トリックマン': '041 Trickman',
  '042 召喚士': '042 Summoner',
  '043 不審者': '043 Suspect',
  '044 スプリガン': '044 Spriggan',
  '045 ボム': '045 Bomb',
  '046 スーパーボム': '046 Super Bomb',
  '047 バードマージ': '047 Bird Merge',
  '048 セイントバード': '048 Saint Bird',
  '049 あざわらう月': '049 Mocking Moon',
  '050 弾丸スター': '050 Bullet Star',
  '051 ベルフェゴ': '051 Belphego',
  '052 水竜': '052 Water',
  '053 火竜': '053 Fire',
  '054 アク': '054 Aqua',
  '055 ポチ': '055 Pochi',
  '056 ダークヤシーユ': '056 Dark Yashiyu',
  '057 ミクトル': '057 Mictor',
  '058 サンタ': '058 Santa',
  '059 ルゴー': '059 Lugar',
  '060 トラップ': '060 Trap',
  '061 スピルト': '061 Spirt',
  'エフェクトの消去': 'Clear Effect',
  '001 クリアボール': '001 Clear Ball',
  '002 クリアボール-透明': '002 Clear Ball(Inv)',
  '003 ジェム': '003 Gem',
  '004 ビッグジェム': '004 Big Gem',
  '005 リターン': '005 Return',
  '006 ハイリターン': '006 Hi Return',
  '007 ラプス': '007 Lapse',
  '008 ハイラプス': '008 Hi Lapse',
  '009 ハート': '009 Heart',
  '010 ビッグハート': '010 Big Heart',
  '011 ×ハート': '011 X Heart',
  '012 シュガー': '012 Sugar',
  '013 ビッグシュガー': '013 Big Sugar',
  '014 ×シュガー': '014 X Sugar',
  '015 ワープ': '015 Warp',
  '016 スクロール-R': '016 Scroll-R',
  '017 スクロール-L': '017 Scroll-L',
  '018 スクロールストップ': '018 Scroll Stop',
  '019 スイッチ': '019 Switch',
  '020 スイッチ-透明': '020 Switch(Inv)',
  '021 押すなスイッチ': '021 Dont Push Sw',
  '022 看板-茶': '022 Sign-Brown',
  '023 看板-灰': '023 Sign-Gray',
  '024 ブーツ': '024 Boots',
  '025 フェザーブーツ': '025 Feather Boots',
  '026 ビッグソード-Z': '026 Big Sword-Z',
  '027 ミラクルソード-Z': '027 Miracle Sw-Z',
  '028 ブロック召喚-Z': '028 Block Sum-Z',
  '029 ダブルショット-C': '029 Double Shot-C',
  '030 ホーミングショット-C': '030 Homing Shot-C',
  '031 トラップ-C': '031 Trap-C',
  '032 スター': '032 Star',
  '033 ○': '033 O',
  '034 ×': '034 X',
  '035 △': '035 △',
  '036 ▽': '036 ▽',
  '037 □': '037 □',
  '038 ◇': '038 ◇',
  '039 →': '039 →',
  '040 ←': '040 ←',
  '041 ↓': '041 ↓',
  '042 ↑': '042 ↑',
  '043 ＝': '043 =',
  '044 ＋': '044 +',
  '045 －': '045 -',
  '046 ／': '046 /',
  '047 ０': '047 0',
  '048 １': '048 1',
  '049 ２': '049 2',
  '050 ３': '050 3',
  '051 ４': '051 4',
  '052 ５': '052 5',
  '053 ６': '053 6',
  '054 ７': '054 7',
  '055 ８': '055 8',
  '056 ９': '056 9',
  '057 ※': '057 *',
  '058 ！': '058 !',
  '059 ？': '059 ?',

  
  '金ジェム18': 'GoldGem18',
  'キャラデータ': 'CharData',
  '説明書': 'Manual',
  '青': 'Bl',

  '過去に取得済みの金Gは済マークが付く': 'Got GoldGems show mark',
  'レアリティに対応したグラ変更フロー': 'Rarity gfx change flow',
  '全て': 'All',
  'ターゲット2がいる方を向く': 'Face Target2',
  'ターゲット2がいる方の逆を向く': 'Face Away T2',
  'ターゲット3がいる方を向く': 'Face Target3',
  'ターゲット3がいる方の逆を向く': 'Face Away T3',
  'ターゲット4がいる方を向く': 'Face Target4',
  'ターゲット4がいる方の逆を向く': 'Face Away T4',
  '・': '.',
  '方向と距離で指定': 'By Dir+Dist',
  'ターゲット1からの方向と距離で指定': 'From T1 Dir+Dist',
  'ターゲット2からの方向と距離で指定': 'From T2 Dir+Dist',
  'ターゲット3からの方向と距離で指定': 'From T3 Dir+Dist',
  'ターゲット4からの方向と距離で指定': 'From T4 Dir+Dist',
  'コンボジェム': 'ComboGem',
  'アイテムデータ': 'ItemData',
  '1回だけ取れる': 'Get Once',
  '何回でも取れる': 'Get Multiple',
  '取れない': 'Cant Get',
  'フローの変更': 'Flow Change',
  '2周目へ突入': 'Strt 2ndLoop',
  'タイトルへ戻る（※非推奨）': 'Back to Title(NotRec)',
  '変数条件なし': 'No Var Cond',
  'ワールド': 'World',
  '道': 'Pt',
  '壁': 'Wl',

  'データベース': 'Database',
  'ＭＳ ゴシック': 'MS Gothic',
  'ＭＳ Ｐゴシック': 'MS P Gothic',
  'ＭＳ 明朝': 'MS Mincho',
  'ＭＳ Ｐ明朝': 'MS P Mincho',
  'HGｺﾞｼｯｸE': 'HG Gothic E',
  'HGPｺﾞｼｯｸE': 'HGP Gothic E',
  'HGSｺﾞｼｯｸE': 'HGS Gothic E',
  'HG丸ｺﾞｼｯｸM-PRO': 'HG MaruGothic M-PRO',
  'HG創英角ｺﾞｼｯｸUB': 'HG Soei Gothic UB',
  'HGP創英角ｺﾞｼｯｸUB': 'HGP Soei Gothic UB',
  'HGS創英角ｺﾞｼｯｸUB': 'HGS Soei Gothic UB',
  'HG創英角ﾎﾟｯﾌﾟ体': 'HG Soei Pop',
  'HGP創英角ﾎﾟｯﾌﾟ体': 'HGP Soei Pop',
  'HGS創英角ﾎﾟｯﾌﾟ体': 'HGS Soei Pop',
  'HG正楷書体-PRO': 'HG Seika-PRO',
  'メイリオ': 'Meiryo',
  'HGｺﾞｼｯｸM': 'HG Gothic M',
  'HGPｺﾞｼｯｸM': 'HGP Gothic M',
  'HGSｺﾞｼｯｸM': 'HGS Gothic M',
  'HG行書体': 'HG Gyosho',
  'HGP行書体': 'HGP Gyosho',
  'HGS行書体': 'HGS Gyosho',
  'HG教科書体': 'HG Textbook',
  'HGP教科書体': 'HGP Textbook',
  'HGS教科書体': 'HGS Textbook',
  'HG明朝B': 'HG Minc B',
  'HGP明朝B': 'HGP Mincho B',
  'HGS明朝B': 'HGS Mincho B',
  'HG明朝E': 'HG Minc E',
  'HGP明朝E': 'HGP Mincho E',
  'HGS明朝E': 'HGS Mincho E',
  'HG創英ﾌﾟﾚｾﾞﾝｽEB': 'HG Soei Presence EB',
  'HGP創英ﾌﾟﾚｾﾞﾝｽEB': 'HGP Soei Presence EB',
  'HGS創英ﾌﾟﾚｾﾞﾝｽEB': 'HGS Soei Presence EB',
  '影': 'Sd',
  '縁': 'Ed',
  '[年]_[月日]_[時分秒]_[ステージファイル名]_[バリエーションの変数番号]_[バリエーションの値]_[ステージクリアしたか]': '[Year]_[MonthDay]_[Time]_[StageFile]_[VarNo]_[VarVal]_[Cleared]',
  '[年]_[月日]_[時分秒]_[ステージ名]_[バリエーションの変数番号]_[バリエーションの値]_[ステージクリアしたか]': '[Year]_[MonthDay]_[Time]_[StageName]_[VarNo]_[VarVal]_[Cleared]',
  '速度重視': 'Speed Pr',
  '互換性重視': 'Compat Pr',
  'システムの設定': 'SysSettings',
  'オートセーブOFFでゲーム開始': 'Start No AutoSave',
  '保存先を選択してオートセーブONで開始': 'Start With AutoSave',
  '保存先は1番で固定、常時オートセーブON': 'Slot1 Fixed AutoSave',

  '8bit(256色)': '8bit(256cl)',
  'このデータを使ってステージを作って下さい': 'Use this data to make stage',
  '右方向へ拡張（または右を削除）': 'Extend right (or del right)',
  '左方向へ拡張（または左を削除）': 'Extend left (or del left)',
  '下方向へ拡張（または下を削除）': 'Extend down (or del down)',
  '上方向へ拡張（または上を削除）': 'Extend up (or del up)',
  '主人公の位置に合わせてスクロール': 'Scroll with hero',
  'オートスクロール': 'Auto scroll',
  '隠れる幅 0(bl)': 'Hide width 0(bl)',
  'ステージの設定': 'Stage settings',
  'レベル1 (速度制限=60)': 'Lv1 (spd lim=60)',
  'レベル2 (速度制限=120)': 'Lv2 (spd lim=120)',
  'レベル3 (速度制限=180)': 'Lv3 (spd lim=180)',
  'レベル4 (速度制限=240)': 'Lv4 (spd lim=240)',
  'レベル5 (速度制限=300)': 'Lv5 (spd lim=300)',
  'レベル6 (速度制限=360)': 'Lv6 (spd lim=360)',
  'レベル7 (速度制限=420)': 'Lv7 (spd lim=420)',
  'レベル8 (速度制限=480)': 'Lv8 (spd lim=480)',
  'レベル9 (速度制限=540)': 'Lv9 (spd lim=540)',
  'レベル10 (速度制限=600)': 'Lv10 (spd lim=600)',
  'レベル1 (速度制限=600)': 'Lv1 (spd lim=600)',
  'レベル2 (速度制限=600)': 'Lv2 (spd lim=600)',
  'レベル3 (速度制限=600)': 'Lv3 (spd lim=600)',
  'レベル4 (速度制限=600)': 'Lv4 (spd lim=600)',
  'レベル5 (速度制限=600)': 'Lv5 (spd lim=600)',
  'レベル6 (速度制限=600)': 'Lv6 (spd lim=600)',
  'レベル7 (速度制限=600)': 'Lv7 (spd lim=600)',
  'レベル8 (速度制限=600)': 'Lv8 (spd lim=600)',
  'レベル9 (速度制限=600)': 'Lv9 (spd lim=600)',
  '最大 (当たり判定レベルと同じ)': 'Max (same as hit Lv)',
  '1 (対応速度=60)': '1 (spd=60)',
  '2 (対応速度=最大120)': '2 (spd=max120)',
  '3 (対応速度=最大180)': '3 (spd=max180)',
  '4 (対応速度=最大240)': '4 (spd=max240)',
  '5 (対応速度=最大300)': '5 (spd=max300)',
  '中央': 'Cntr',
  '枠のみ表示': 'Frame only',
  '虹': 'Rb',
  '歩行時：対ブロック (16,24,下)': 'Walk:vsBlk (16,24,B)',
  '飛行時：対ブロック (16,16,中)': 'Fly:vsBlk (16,16,C)',
  '歩行時：対キャラ (16,24,下)': 'Walk:vsChar (16,24,B)',
  '飛行時：対キャラ (16,16,中)': 'Fly:vsChar (16,16,C)',
  '対アイテム (16,16)': 'vsItem (16,16)',
  '対ショット (12,8)': 'vsShot (12,8)',
  '歩行時：対ブロック (16,24,下)': 'Walk:vsBlk (16,24,B)',
  '飛行時：対ブロック (16,16,中)': 'Fly:vsBlk (16,16,C)',
  '歩行時：対キャラ (12,24,下)': 'Walk:vsChar (12,24,B)',
  '飛行時：対キャラ (12,16,中)': 'Fly:vsChar (12,16,C)',
  '対ショット (30,30)': 'vsShot (30,30)',
  '対キャラ (28,28)': 'vsChar (28,28)',
  '対キャラ (16,16)': 'vsChar (16,16)',
  '対ショット (16,16)': 'vsShot (16,16)',

  '[コモン]ブロックパレット': '[Common]Block Palette',
  '[ステージ]ブロックパレット': '[Stage]Block Palette',
  '[コモン]キャラパレット': '[Common]Char Palette',
  '[ステージ]キャラパレット': '[Stage]Char Palette',
  '[コモン]アイテムパレット': '[Common]Item Palette',
  '[ステージ]アイテムパレット': '[Stage]Item Palette',

  '破裂': 'Brst',
  '分割（横）': 'Split(H)',
  '分割（縦）': 'Split(V)',
  '波（横）': 'Wave(H)',
  '波（縦）': 'Wave(V)',
  '点滅': 'Blnk',
  '回転A': 'Rot A',
  '回転B': 'Rot B',
  '回転（奥）': 'Rot (Bk)',
  '円': 'Cl',
  '拡大': 'Zoom',
  'レンズ': 'Lens',
  '色変化': 'Color',
  '半透明': 'Transp',
  'モザイク': 'Mosaic',
  'ぼかし': 'Blur',
  'Direct3D有効時：\nDirect3D無効時：やや遅い': 'D3D on:\nD3D off: slow',
  '実行時間(1/10s)': 'Duration(1/10s)',
  '開始幅(dot)': 'Start width(dot)',
  '終了幅(dot)': 'End width(dot)',
  '波の数': 'Wave c',
  '波の粗さ(dot)': 'Wave rough(dot)',
  'Direct3D有効時：\nDirect3D無効時：画面が8bit色→精度悪い、16bit色以上→遅過ぎ': 'D3D on:\nD3D off: 8bit=bad, 16bit+=slow',
  '点滅間隔(1/60s)': 'Blink int(1/60s)',
  'Direct3D有効時：\nDirect3D無効時：画面が16bit色以上だと遅い': 'D3D on:\nD3D off: 16bit+=slow',
  '開始強度': 'Start st',
  '終了強度': 'End st',
  'Direct3D有効時：やや遅い\nDirect3D無効時：画面が16bit色以上でのみ有効。遅い': 'D3D on: slow\nD3D off: 16bit+ only. slow',
  'Direct3D有効時：速い\nDirect3D無効時：速い': 'D3D on: fast\nD3D off: fast',
  'Direct3D有効時：回転Aと回転Bは同じ\nDirect3D無効時：巨大キャラには実行速度重視': 'D3D on: RotA=RotB\nD3D off: big char=spd',
  '開始角度': 'Start ng',
  '終了角度': 'End ng',
  'Direct3D有効時：回転Aと回転Bは同じ\nDirect3D無効時：やや遅い。巨大キャラには描画精度重視': 'D3D on: RotA=RotB\nD3D off: slow. big char=qual',
  'Direct3D有効時：\nDirect3D無効時：': 'D3D on:\nD3D off:',
  '開始位置(dot)': 'Start pos(dot)',
  '終了位置(dot)': 'End pos(dot)',
  '開始半径(dot)': 'Start rad(dot)',
  '終了半径(dot)': 'End rad(dot)',
  '円の粗さ(dot)': 'Circle rough(dot)',
  'Direct3D有効時：遅過ぎ\nDirect3D無効時：遅い': 'D3D on: too slow\nD3D off: slow',
  '開始距離': 'Strt dst',
  '終了距離': 'End dst',
  'ズレX(dot)': 'Offset X(dot)',
  'ズレY(dot)': 'Offset Y(dot)',
  'Direct3D有効時：\nDirect3D無効時：画面が8bit色→精度悪い、16bit色以上→やや遅い': 'D3D on:\nD3D off: 8bit=bad, 16bit+=slow',
  '開始合成度': 'Strt blnd',
  '終了合成度': 'End blend',
  '色': 'Cl',
  '振動幅(dot)': 'Vib width(dot)',
  '振動回数': 'Vib cnt',
  '開始座標X(dot)': 'Start X(dot)',
  '開始座標Y(dot)': 'Start Y(dot)',
  '終了座標X(dot)': 'End X(dot)',
  '終了座標Y(dot)': 'End Y(dot)',
  '分割数': 'Split',
  'Direct3D有効時：やや遅い\nDirect3D無効時：やや遅い': 'D3D on: slow\nD3D off: slow',
  'Direct3D有効時：遅過ぎ\nDirect3D無効時：遅過ぎ': 'D3D on: too slow\nD3D off: too slow',
  'Direct3D有効時：遅過ぎ\nDirect3D無効時：画面が16bit色以上だと遅過ぎ': 'D3D on: too slow\nD3D off: 16bit+=too slow',
  'Direct3D有効時：\nDirect3D無効時：遅い': 'D3D on:\nD3D off: slow',
  '移動': 'Move',
  '振動（横）': 'Vib(H)',
  '振動（縦）': 'Vib(V)',
  '回転': 'Rot',
  '当たらない': 'No hit',
  '当たる': 'Hit',
  '主人公が当たると即死': 'Hero hit=insta death',
  'ジャンプ X=高さ(hbl)': 'Jump X=height(hbl)',
  'ジャンプ禁止': 'No jump',
  '移動速度変更 X=％': 'Move spd chg X=%',
  '左移動 X=移動速度': 'Move L X=spd',
  '右移動 X=移動速度': 'Move R X=spd',
  'ブロックデータ': 'BlockData',
  'ブロックに乗っている(ブロックキャラも含む)': 'On block(inc block char)',
  '画面内にいる': 'On screen',
  '存在している': 'Exists',
  'なら': 'If',
  'でないなら': 'If not',
  '時間': 'Time',
  '横スクロール速度': 'H scroll spd',
  '縦スクロール速度': 'V scroll spd',
  'スコア': 'Score',
  '残り人数': 'Lives',

  //Messages Box
  'ステージが変更された可能性があります。\n保存しますか？': 'Stage may have changed.\nSave?',
  '保存確認': 'Confirm',
  'バックアップ': 'Backup',
  'ワールドマップが変更された可能性があります。\n保存しますか？': 'World map may have changed.\nSave?',
  'エディットデータをバックアップしています...': 'Backing up edit data...',
  '旧バージョンのステージファイルを「old_ver」フォルダへ移動': 'Move old stage files to "old_ver"',
  '旧バージョンのステージファイルをそのまま残す': 'Keep old stage files',
  '旧バージョンのステージファイルを削除': 'Delete old stage files',
  'プロジェクトオプション': 'Project Options',
  'データが存在しません！デフォルトデータを作成しますか？\n': 'No data exists! Create default data?',
  'デフォルトデータ作成の確認': 'Confirm creation'
};


// Optional quick sanity
function validateTranslations(translations) {
  for (const [k, v] of Object.entries(translations)) {
    if (v.length > k.length * 2)
      console.log(` ✗ TOO LONG : "${v}"`);
  }
}
validateTranslations(TRANSLATIONS);

// -----------------------------
// User32 hooks (Frida 17 style)
// -----------------------------
waitForModule('user32.dll', 3000);
const user32 = Process.getModuleByName('user32.dll');

// Resolve exports via instance API
const sendMessageAPtr   = user32.findExportByName('SendMessageA');
const sendMessageWPtr   = user32.findExportByName('SendMessageW');
const setWindowTextAPtr = user32.findExportByName('SetWindowTextA');
const setWindowTextWPtr = user32.findExportByName('SetWindowTextW');
const messageBoxAPtr    = user32.findExportByName('MessageBoxA');

const WM_SETTEXT = 0x000C;
const CB_ADDSTRING = 0x0143;
const CB_INSERTSTRING = 0x0144;

// --- SendMessageA ---
if (sendMessageAPtr) {
  Interceptor.attach(sendMessageAPtr, {
    onEnter(args) {
      const msg = args[1].toInt32();
      const lParam = args[3];
      if (lParam.isNull()) return;
      if (msg !== CB_ADDSTRING && msg !== CB_INSERTSTRING && msg !== WM_SETTEXT) return;

      const origPtr = lParam;
      const origByteLen = getAnsiByteLength(origPtr);
      const origText = sjisPtrToUtf8(origPtr);
      if (!origText) return;

      // Skip numeric/path/pure-ASCII
      if (/^\d{2,3}|^\.\\/.test(origText)) return;
      if (isAscii(origText)) return;

      if (Object.prototype.hasOwnProperty.call(TRANSLATIONS, origText)) {
        const en = TRANSLATIONS[origText];
        try { writePaddedAnsiString(origPtr, origByteLen, en); }
        catch (e) { console.warn(`  → Overwrite failed: ${e.message}`); }
      } else {
        console.log(`TODO: "${origText}" (SendMessageA)`);
      }
    }
  });
  console.log('[+] Hooked SendMessageA (ANSI only)');
} else {
  console.log('[-] SendMessageA not found');
}

// --- SendMessageW ---
if (sendMessageWPtr) {
  Interceptor.attach(sendMessageWPtr, {
    onEnter(args) {
      const msg = args[1].toInt32();
      const lParam = args[3];
      if (lParam.isNull()) return;

      let origText = null, isDropdown = false;
      if (msg === CB_ADDSTRING || msg === CB_INSERTSTRING) {
        origText = readWideString(lParam); isDropdown = true;
      } else if (msg === WM_SETTEXT) {
        origText = readWideString(lParam);
      }

      if (origText && TRANSLATIONS[origText]) {
        const en = TRANSLATIONS[origText];
        if (isAscii(en)) {
          args[3] = Memory.allocUtf16String(en);
        }
      }
    }
  });
  console.log('[+] Hooked SendMessageW (Unicode dropdowns)');
} else {
  console.log('[-] SendMessageW not found');
}

// --- SetWindowTextA ---
if (setWindowTextAPtr) {
  Interceptor.attach(setWindowTextAPtr, {
    onEnter(args) {
      const p = args[1];
      if (p.isNull()) return;

      const origByteLen = getAnsiByteLength(p);
      const origText = sjisPtrToUtf8(p);
      if (!origText || isAscii(origText)) return;
      if (origText.startsWith('.\\')) return;

      // Special case: replace "アクションエディター4" in window titles
      if (origText.startsWith('アクションエディター4')) {
        const en = origText.replace('アクションエディター4', 'Aquedi4');
        try { writePaddedAnsiString(p, origByteLen, en); return; }
        catch (e) { console.warn(`  → Overwrite failed: ${e.message}`); }
      }

      if (Object.prototype.hasOwnProperty.call(TRANSLATIONS, origText)) {
        const en = TRANSLATIONS[origText];
        try { writePaddedAnsiString(p, origByteLen, en); }
        catch (e) { console.warn(`  → Overwrite failed: ${e.message}`); }
      } else {
        console.log(`TODO: "${origText}"`);
      }
    }
  });
  console.log('[+] Hooked SetWindowTextA (ANSI only)');
} else {
  console.log('[-] SetWindowTextA not found');
}

// --- SetWindowTextW ---
if (setWindowTextWPtr) {
  Interceptor.attach(setWindowTextWPtr, {
    onEnter(args) {
      const p = args[1];
      if (p.isNull()) return;
      const orig = readWideString(p);
      if (orig && TRANSLATIONS[orig]) {
        const en = TRANSLATIONS[orig];
        if (isAscii(en)) args[1] = Memory.allocUtf16String(en);
      }
    }
  });
  console.log('[+] Hooked SetWindowTextW');
} else {
  console.log('[-] SetWindowTextW not found');
}

// --- MessageBoxA ---
if (messageBoxAPtr) {
  Interceptor.attach(messageBoxAPtr, {
    onEnter(args) {
      const textPtr = args[1];
      const captionPtr = args[2];

      if (!textPtr.isNull()) {
        const t = sjisPtrToUtf8(textPtr);
        if (t && Object.prototype.hasOwnProperty.call(TRANSLATIONS, t)) {
          const en = TRANSLATIONS[t];
          const len = getAnsiByteLength(textPtr);
          try { writePaddedAnsiString(textPtr, len, en); }
          catch (e) { console.warn(`  → Text overwrite failed: ${e.message}`); }
        } else if (t && !isAscii(t) && !/^\d{2,3}/.test(t)) {
          console.log(`TODO (MessageBox TEXT): "${t}"`);
        }
      }

      if (!captionPtr.isNull()) {
        const c = sjisPtrToUtf8(captionPtr);
        if (c && !c.startsWith('.\\') && Object.prototype.hasOwnProperty.call(TRANSLATIONS, c)) {
          const en = TRANSLATIONS[c];
          const len = getAnsiByteLength(captionPtr);
          try { writePaddedAnsiString(captionPtr, len, en); }
          catch (e) { console.warn(`  → Caption overwrite failed: ${e.message}`); }
        } else if (c && !isAscii(c) && !/^\d{2,3}/.test(c)) {
          console.log(`TODO: "${c}"`);
        }
      }
    }
  });
  console.log('[+] Hooked MessageBoxA');
} else {
  console.log('[-] MessageBoxA not found');
}

// -----------------------------
// Module bases (Frida 17 style)
// -----------------------------
const mainMod = Process.findModuleByName('Editor_v1020.exe');
if (!mainMod) {
  console.log('[!] Failed to find module base for Editor_v1020.exe');
} else {
  console.log('[+] Module base:', mainMod.base);
}

// Optional: show a disclaimer box once
if (messageBoxAPtr) {
  const MessageBoxA = new NativeFunction(
    messageBoxAPtr,
    'int', ['pointer','pointer','pointer','uint']
  );
  const msg = Memory.allocUtf8String(
`String Swap Translator Active!

Please note this is a beta/test
Don't make translation longer than the JP text !!
If you know Frida/Win32/Detours/Hooking, please PM me with fixes.

Foxxo ~`
  );
  const title = Memory.allocUtf8String('DISCLAIMER :: AQU3DiTR4NSLAT0R :: Do expect bugs !');
  MessageBoxA(NULL, msg, title, 0x40); // MB_ICONINFORMATION
}
