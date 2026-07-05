require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 8080;
const USERS_FILE = path.join(__dirname, "data", "users.json");
const TOPUPS_FILE = path.join(__dirname, "data", "topup_requests.json");

const IS_PROD = process.env.NODE_ENV === "production";

if (IS_PROD && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 16)) {
  console.error("ERRO: defina a variável de ambiente SESSION_SECRET antes de subir em produção.");
  process.exit(1);
}

function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf-8")); } catch { return fallback; }
}
function saveJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

let users = loadJson(USERS_FILE, {});
let topupRequests = loadJson(TOPUPS_FILE, []);
function saveUsers() { saveJson(USERS_FILE, users); }
function saveTopups() { saveJson(TOPUPS_FILE, topupRequests); }

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const hashBuf = Buffer.from(hash, "hex");
  const attempt = crypto.scryptSync(password, salt, 64);
  if (attempt.length !== hashBuf.length) return false;
  return crypto.timingSafeEqual(hashBuf, attempt);
}

function round2(n) { return Math.round(n * 100) / 100; }
function dayKey(date) {
  const offsetMs = 3 * 60 * 60 * 1000; // Brasília = UTC-3
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 10);
}
function totalBalance(user) { return round2((user.bonusBalance || 0) + (user.winningsBalance || 0)); }


function debitBet(user, amount) {
  let remaining = amount;
  const fromBonus = Math.min(user.bonusBalance, remaining);
  user.bonusBalance = round2(user.bonusBalance - fromBonus);
  remaining = round2(remaining - fromBonus);
  if (remaining > 0) user.winningsBalance = round2(user.winningsBalance - remaining);
  user.wageredSinceLastWithdraw = round2((user.wageredSinceLastWithdraw || 0) + amount);
  const key = dayKey(new Date());
  if (!user.dailyActivity) user.dailyActivity = {};
  if (!user.dailyActivity[key]) user.dailyActivity[key] = { wagered: 0, games: 0 };
  user.dailyActivity[key].wagered = round2(user.dailyActivity[key].wagered + amount);
  user.dailyActivity[key].games += 1;
  pruneDailyActivity(user);
}

const DAILY_ACTIVITY_RETENTION_DAYS = 45;
function pruneDailyActivity(user) {
  if (!user.dailyActivity) return;
  const cutoff = Date.now() - DAILY_ACTIVITY_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  for (const key of Object.keys(user.dailyActivity)) {
    if (new Date(key + "T00:00:00Z").getTime() < cutoff) delete user.dailyActivity[key];
  }
}

function creditWin(user, amount) { user.winningsBalance = round2(user.winningsBalance + amount); }

function checkDailyReset(user) {
  const today = dayKey(new Date());
  if (user.lastDailyReset !== today) {
    user.lastDailyReset = today;
    user.history = [];
    user.depositCount = 0;
    user.totalDeposited = 0;
    user.totalGamesPlayed = 0;
    saveUsers();
  }
}

function migrateUserShape(user) {
  if (typeof user.bonusBalance !== "number") user.bonusBalance = typeof user.balance === "number" ? user.balance : 3;
  if (typeof user.winningsBalance !== "number") user.winningsBalance = 0;
  if (typeof user.totalGamesPlayed !== "number") user.totalGamesPlayed = (user.history || []).length;
  if (typeof user.wageredSinceLastWithdraw !== "number") user.wageredSinceLastWithdraw = 0;
  if (user.lastWithdrawAt === undefined) user.lastWithdrawAt = null;
  if (typeof user.dailyActivity !== "object" || user.dailyActivity === null) user.dailyActivity = {};
  if (typeof user.accountCreatedAt !== "string") user.accountCreatedAt = new Date().toISOString();
  if (typeof user.depositCount !== "number") user.depositCount = 0;
if (typeof user.totalDeposited !== "number") user.totalDeposited = 0;
  delete user.balance;
}

app.set("trust proxy", 1);
app.use(helmet({
  hsts: false,
  crossOriginOpenerPolicy: false,
  originAgentCluster: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));

app.use(express.json({ limit: "10kb" }));
app.use(session({
  name: "mines.sid",
  secret: process.env.SESSION_SECRET || "dev-only-secret-troque-via-env-SESSION_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 4, httpOnly: true, sameSite: "lax", secure: IS_PROD }
}));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: "Muitas tentativas. Aguarde alguns minutos e tente novamente." }
});
const topupLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: "Muitas solicitações de pagamento. Aguarde um pouco e tente de novo." }
});

app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  const key = req.session.username;
  if (!key || !users[key]) return res.status(401).json({ error: "Não autenticado" });
  migrateUserShape(users[key]);
  checkDailyReset(users[key]);
  next();
}
function validarCPF(cpf) {
  cpf = cpf.replace(/\D/g, "");
  if (cpf.length !== 11) return false;
  if (/^(\d)\1+$/.test(cpf)) return false;
  let soma = 0;
  for (let i = 0; i < 9; i++) {
    soma += Number(cpf[i]) * (10 - i);
  }
  let resto = (soma * 10) % 11;
  if (resto === 10) resto = 0;
  if (resto !== Number(cpf[9])) return false;
  soma = 0;
  for (let i = 0; i < 10; i++) {
    soma += Number(cpf[i]) * (11 - i);
  }
  resto = (soma * 10) % 11;
  if (resto === 10) resto = 0;
  return resto === Number(cpf[10]);
}

app.post("/api/register", authLimiter, (req, res) => {
  const { cpf, password } = req.body || {};
  if (typeof cpf !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "CPF e senha são obrigatórios" });
  }
  const cpfLimpo = cpf.replace(/\D/g, "");
  if (!validarCPF(cpfLimpo)) {
    return res.status(400).json({ error: "CPF inválido" });
  }
  if (password.length < 4 || password.length > 200) {
    return res.status(400).json({ error: "A senha deve ter no mínimo 4 caracteres" });
  }
  const key = cpfLimpo;
  if (users[key]) {
    return res.status(409).json({ error: "Já existe uma conta com esse CPF" });
  }

users[key] = {
    passwordHash: hashPassword(password),
    bonusBalance: 3,
    winningsBalance: 0,
    totalGamesPlayed: 0,
    wageredSinceLastWithdraw: 0,
    lastWithdrawAt: null,
    dailyActivity: {},
    accountCreatedAt: new Date().toISOString(),
    history: [],

    depositCount: 0,
    totalDeposited: 0
};
  saveUsers();
  req.session.regenerate(() => {
    req.session.username = key;
    res.json({ username: key, balance: totalBalance(users[key]) });
  });
});

app.post("/api/login", authLimiter, (req, res) => {
  const { cpf, password } = req.body || {};

  const key = typeof cpf === "string"
    ? cpf.replace(/\D/g, "")
    : "";

  const user = users[key];

  if (!user || !verifyPassword(password || "", user.passwordHash)) {
    return res.status(401).json({ error: "CPF ou senha inválidos" });
  }

  migrateUserShape(user);

  req.session.regenerate(() => {
    req.session.username = key;
    res.json({
      username: key,
      balance: totalBalance(user)
    });
  });
});

app.post("/api/logout", (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

app.get("/api/me", (req, res) => {
  const key = req.session.username;
  if (!key || !users[key]) return res.status(401).json({ error: "Não autenticado" });
  const user = users[key];
  migrateUserShape(user);
  checkDailyReset(user);
  res.json({ username: key, balance: totalBalance(user) });
});

app.get("/api/history", requireAuth, (req, res) => {
  const user = users[req.session.username];
  res.json({ history: (user.history || []).slice(-50).reverse() });
});

function pushHistory(username, entry) {
  const user = users[username];
  if (!user.history) user.history = [];
  user.history.push(entry);
  if (user.history.length > 200) {
    user.history = user.history.slice(-200);
  }
}

// Depósito: pacotes menores — R$ 5, 10, 15, 20, 25
const ALLOWED_TOPUP_AMOUNTS = [5, 10, 15, 20, 25];

app.post("/api/topup/request", requireAuth, topupLimiter, (req, res) => {
  const amount = Number(req.body.amount);
  if (!ALLOWED_TOPUP_AMOUNTS.includes(amount)) {
    return res.status(400).json({ error: "Valor de recarga inválido" });
  }
  const request = { id: crypto.randomUUID(), username: req.session.username, amount, status: "pending", createdAt: new Date().toISOString() };
  topupRequests.push(request);
  saveTopups();
  res.json({ requestId: request.id, status: "pending" });
});

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: "Painel admin não configurado (defina ADMIN_TOKEN)" });
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_TOKEN) return res.status(403).json({ error: "Token inválido" });
  next();
}

app.get("/api/admin/topups", requireAdmin, (req, res) => {
  const pending = topupRequests.filter(r => r.status === "pending");
  const recent = topupRequests.filter(r => r.status !== "pending").slice(-15).reverse();
  res.json({ pending, recent });
});

app.post("/api/admin/topups/:id/confirm", requireAdmin, (req, res) => {
  const request = topupRequests.find(r => r.id === req.params.id);
  if (!request || request.status !== "pending") return res.status(404).json({ error: "Solicitação não encontrada ou já processada" });
  const user = users[request.username];
  if (!user) return res.status(404).json({ error: "Usuário não existe mais" });
  migrateUserShape(user);
  user.bonusBalance = round2(user.bonusBalance + request.amount);
user.depositCount = (user.depositCount || 0) + 1;
user.totalDeposited = round2((user.totalDeposited || 0) + request.amount);
  request.status = "confirmed";
  request.confirmedAt = new Date().toISOString();
  saveUsers(); saveTopups();
  res.json({ ok: true, balance: totalBalance(user) });
});

app.post("/api/admin/topups/:id/reject", requireAdmin, (req, res) => {
  const request = topupRequests.find(r => r.id === req.params.id);
  if (!request || request.status !== "pending") return res.status(404).json({ error: "Solicitação não encontrada ou já processada" });
  request.status = "rejected";
  request.rejectedAt = new Date().toISOString();
  saveTopups();
  res.json({ ok: true });
});

const WITHDRAW_MIN_WINNINGS = 300;
const WITHDRAW_MIN_WAGERED = 500;
const WITHDRAW_WAGER_MULTIPLIER = 4;
const WITHDRAW_MIN_ACTIVE_DAYS = 1;
const WITHDRAW_MIN_DAILY_WAGER = 30;
const WITHDRAW_MIN_DAILY_GAMES = 20;
const WITHDRAW_MIN_ACCOUNT_AGE_DAYS = 7;
const WITHDRAW_COOLDOWN_MS = 1000 * 60 * 60 * 24;
const WITHDRAW_MAX_PERCENT = 0.5;

function countValidActiveDays(user) {
  const activity = user.dailyActivity || {};
  let count = 0;
  for (const key of Object.keys(activity)) {
    const day = activity[key];
    if (day.wagered >= WITHDRAW_MIN_DAILY_WAGER && day.games >= WITHDRAW_MIN_DAILY_GAMES) count++;
  }
  return count;
}
function accountAgeDays(user) {
  if (!user.accountCreatedAt) return 0;
  return Math.floor((Date.now() - new Date(user.accountCreatedAt).getTime()) / (1000 * 60 * 60 * 24));
}
function requiredWageredFor(amountIntendedOrNull, user) {
  const reference = amountIntendedOrNull != null ? amountIntendedOrNull : round2(user.winningsBalance * WITHDRAW_MAX_PERCENT);
  return Math.max(WITHDRAW_MIN_WAGERED, round2(reference * WITHDRAW_WAGER_MULTIPLIER));
}
function evaluateWithdrawEligibility(user, amountIntended) {
  const reasons = [];
 if ((user.depositCount || 0) < 1) {
  reasons.push("Faça pelo menos 1 depósito.");
}

if ((user.totalDeposited || 0) < 30) {
  reasons.push(
    `Deposite pelo menos R$ 30,00 (atual: R$ ${(user.totalDeposited || 0).toFixed(2)}).`
  );
}
if (user.totalGamesPlayed < 100) {
  reasons.push(
    `Jogue pelo menos 100 partidas (atual: ${user.totalGamesPlayed}).`
  );
}
  const activeDays = countValidActiveDays(user);
  if (activeDays < WITHDRAW_MIN_ACTIVE_DAYS) reasons.push(`Jogue em pelo menos ${WITHDRAW_MIN_ACTIVE_DAYS} dias diferentes, apostando >= R$ ${WITHDRAW_MIN_DAILY_WAGER.toFixed(2)} e jogando >= ${WITHDRAW_MIN_DAILY_GAMES} partidas em cada um (dias válidos até agora: ${activeDays}).`);
  if (user.winningsBalance < WITHDRAW_MIN_WINNINGS) reasons.push(`Tenha pelo menos R$ ${WITHDRAW_MIN_WINNINGS.toFixed(2)} em saldo ganho jogando (atual: R$ ${user.winningsBalance.toFixed(2)}).`);
  const requiredWagered = requiredWageredFor(amountIntended, user);
  if (user.wageredSinceLastWithdraw < requiredWagered) reasons.push(`Aposte pelo menos R$ ${requiredWagered.toFixed(2)} desde o último saque (apostado até agora: R$ ${user.wageredSinceLastWithdraw.toFixed(2)}).`);
  const ageDays = accountAgeDays(user);
  if (ageDays < WITHDRAW_MIN_ACCOUNT_AGE_DAYS) reasons.push(`A conta precisa ter pelo menos ${WITHDRAW_MIN_ACCOUNT_AGE_DAYS} dias de existência (atual: ${ageDays}).`);
  if (user.lastWithdrawAt) {
    const elapsed = Date.now() - new Date(user.lastWithdrawAt).getTime();
    if (elapsed < WITHDRAW_COOLDOWN_MS) {
      const hoursLeft = Math.ceil((WITHDRAW_COOLDOWN_MS - elapsed) / (1000 * 60 * 60));
      reasons.push(`Só é possível sacar uma vez a cada 24h. Aguarde mais ${hoursLeft}h.`);
    }
  }
  const maxAmount = round2(user.winningsBalance * WITHDRAW_MAX_PERCENT);
  return {
    eligible: reasons.length === 0, reasons, maxAmount: Math.max(maxAmount, 0),
    minWinnings: WITHDRAW_MIN_WINNINGS, minWagered: requiredWagered,
    minActiveDays: WITHDRAW_MIN_ACTIVE_DAYS, minDailyWager: WITHDRAW_MIN_DAILY_WAGER,
    minDailyGames: WITHDRAW_MIN_DAILY_GAMES, minAccountAgeDays: WITHDRAW_MIN_ACCOUNT_AGE_DAYS,
    accountAgeDays: ageDays, activeDays, wageredSinceLastWithdraw: user.wageredSinceLastWithdraw,
    totalGamesPlayed: user.totalGamesPlayed, winningsBalance: user.winningsBalance,
    depositCount: user.depositCount || 0,
    totalDeposited: user.totalDeposited || 0
  };
}

app.get("/api/withdraw/status", requireAuth, (req, res) => {
  const user = users[req.session.username];
  const amountParam = Number(req.query.amount);
  const amountIntended = Number.isFinite(amountParam) && amountParam > 0 ? round2(amountParam) : null;
  res.json(evaluateWithdrawEligibility(user, amountIntended));
});

app.post("/api/withdraw/request", requireAuth, (req, res) => {
  const user = users[req.session.username];
  let amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: "Valor de saque inválido" });
  amount = round2(amount);
  const status = evaluateWithdrawEligibility(user, amount);
  if (!status.eligible) return res.status(400).json({ error: "Requisitos de saque não atendidos", reasons: status.reasons });
  const pixKey = typeof req.body.pixKey === "string" ? req.body.pixKey.trim() : "";
  if (!pixKey || pixKey.length < 5 || pixKey.length > 140) return res.status(400).json({ error: "Informe uma chave Pix válida" });
  if (amount > status.maxAmount) return res.status(400).json({ error: `Valor acima do limite por saque (máx. R$ ${status.maxAmount.toFixed(2)})` });
  user.lastWithdrawAt = new Date().toISOString();
  user.wageredSinceLastWithdraw = 0;
  saveUsers();
  res.json({ ok: true, simulated: true, amount: amount.toFixed(2), pixKeyMasked: pixKey.length > 6 ? pixKey.slice(0, 3) + "•••" + pixKey.slice(-3) : "•••", message: "Saque simulado registrado com sucesso (nenhum valor real foi transferido)." });
});
// http://10.0.0.104:3000
const BOARD_SIZES = {
  "4x4": { rows: 4, cols: 4, total: 16 },
  "5x4": { rows: 4, cols: 5, total: 20 },
  "5x5": { rows: 5, cols: 5, total: 25 }
};
const DEFAULT_BOARD_SIZE = "5x4";

// Aposta: R$ 1 a R$ 500, qualquer valor inteiro
const MIN_BET = 1;
const MAX_BET = 500;

// Edge fixo enquanto tem poucas bombas, diminui conforme bombas aumentam
const HOUSE_EDGE_BASE = 0.50;
const HOUSE_EDGE_MIN  = 0.15;
const HOUSE_EDGE_REF_BOMBS = 3;

// Amortecimento da curva: quanto mais bombas, menor o expoente (achata o crescimento)
const DAMP_MAX = 1.0;   // sem amortecimento com poucas bombas
const DAMP_MIN = 0.65;  // achata bastante com muitas bombas

function dynamicHouseEdge(totalCells, bombs) {
  const maxBombs = totalCells - 1;
  if (bombs <= HOUSE_EDGE_REF_BOMBS) return HOUSE_EDGE_BASE;
  const t = (bombs - HOUSE_EDGE_REF_BOMBS) / (maxBombs - HOUSE_EDGE_REF_BOMBS);
  return HOUSE_EDGE_BASE - t * (HOUSE_EDGE_BASE - HOUSE_EDGE_MIN);
}

function dynamicDamping(totalCells, bombs) {
  const maxBombs = totalCells - 1;
  if (bombs <= HOUSE_EDGE_REF_BOMBS) return DAMP_MAX;
  const t = (bombs - HOUSE_EDGE_REF_BOMBS) / (maxBombs - HOUSE_EDGE_REF_BOMBS);
  return DAMP_MAX - t * (DAMP_MAX - DAMP_MIN);
}

function calcMultiplier(totalCells, bombs, opened) {
  let m = 1;
  for (let i = 0; i < opened; i++) m *= (totalCells - i) / (totalCells - bombs - i);
  const damp = dynamicDamping(totalCells, bombs);
  const dampedM = Math.pow(m, damp); // achata o crescimento conforme mais bombas
  return dampedM * dynamicHouseEdge(totalCells, bombs);
}
const games = {};

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
}


app.post("/api/start", requireAuth, (req, res) => {
  const username = req.session.username;
  const user = users[username];
  const sizeKey = BOARD_SIZES[req.body.boardSize] ? req.body.boardSize : DEFAULT_BOARD_SIZE;
  const { total: totalCells } = BOARD_SIZES[sizeKey];
  let bombs = Number(req.body.bombs);
  let bet = Number(req.body.bet);
  const MIN_BOMBS = 3;
  const MAX_BOMBS = totalCells - 1;
  if (!Number.isInteger(bombs) || bombs < MIN_BOMBS) bombs = MIN_BOMBS;
  if (bombs > MAX_BOMBS) bombs = MAX_BOMBS;
  bet = round2(bet);
  if (!Number.isFinite(bet) || bet < MIN_BET || bet > MAX_BET) {
    return res.status(400).json({ error: `Aposta inválida. Mínimo R$ ${MIN_BET.toFixed(2)}, máximo R$ ${MAX_BET.toFixed(2)}.` });
  }
  // Garante que a aposta seja em centavos inteiros (sem casas além de 2)
  if (Math.round(bet * 100) !== bet * 100) {
    return res.status(400).json({ error: "Aposta deve ter no máximo 2 casas decimais." });
  }
  if (bet > totalBalance(user)) return res.status(400).json({ error: "Saldo insuficiente" });
  const hasActiveGame = Object.values(games).some(g => g.username === username && !g.finished);
  if (hasActiveGame) return res.status(400).json({ error: "Você já tem uma partida em andamento" });
  const id = crypto.randomUUID();
  const board = Array(totalCells).fill(false);
  const positions = [...Array(totalCells).keys()];
  shuffle(positions);
  for (let i = 0; i < bombs; i++) board[positions[i]] = true;
  debitBet(user, bet);
  user.totalGamesPlayed = (user.totalGamesPlayed || 0) + 1;
  saveUsers();
  games[id] = { username, bombs, bet, board, totalCells, boardSize: sizeKey, opened: [], finished: false, _createdAt: Date.now() };
  res.json({ gameId: id, balance: totalBalance(user), multiplier: "1.00", boardSize: sizeKey, totalCells });
});



app.post("/api/open", requireAuth, (req, res) => {
  const { gameId, index } = req.body || {};
  const username = req.session.username;
  const game = games[gameId];
  if (!game || game.username !== username) return res.status(404).json({ error: "Jogo não encontrado" });
  if (game.finished) return res.status(400).json({ error: "Esse jogo já terminou" });
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= game.totalCells) return res.status(400).json({ error: "Célula inválida" });
  if (game.opened.includes(index)) return res.status(400).json({ error: "Célula já aberta" });
  if (game.board[index]) {
    game.finished = true;
    pushHistory(username, { result: "loss", bet: game.bet, bombs: game.bombs, boardSize: game.boardSize, multiplier: calcMultiplier(game.totalCells, game.bombs, game.opened.length).toFixed(2), payout: 0, at: new Date().toISOString() });
    return res.json({ bomb: true, board: game.board, balance: totalBalance(users[username]) });
  }


  game.opened.push(index);
  const multiplier = calcMultiplier(game.totalCells, game.bombs, game.opened.length);
  const maxSafeCells = game.totalCells - game.bombs;
  const cleared = game.opened.length === maxSafeCells;
  if (cleared) {
    game.finished = true;
    const payout = round2(game.bet * multiplier);
    creditWin(users[username], payout);
    pushHistory(username, { result: "win", bet: game.bet, bombs: game.bombs, boardSize: game.boardSize, multiplier: multiplier.toFixed(2), payout, at: new Date().toISOString() });
    saveUsers();
  }
  res.json({ bomb: false, board: cleared ? game.board : undefined, multiplier: multiplier.toFixed(2), cleared, balance: totalBalance(users[username]) });
});

app.post("/api/cashout", requireAuth, (req, res) => {
  const { gameId } = req.body || {};
  const username = req.session.username;
  const game = games[gameId];
  if (!game || game.username !== username) return res.status(404).json({ error: "Jogo não encontrado" });
  if (game.finished) return res.status(400).json({ error: "Esse jogo já terminou" });
  if (game.opened.length === 0) return res.status(400).json({ error: "Abra ao menos uma célula antes de retirar" });
  const multiplier = calcMultiplier(game.totalCells, game.bombs, game.opened.length);
  const winnings = round2(game.bet * multiplier);
  creditWin(users[username], winnings);
  game.finished = true;
  pushHistory(username, { result: "win", bet: game.bet, bombs: game.bombs, boardSize: game.boardSize, multiplier: multiplier.toFixed(2), payout: winnings, at: new Date().toISOString() });
  saveUsers();
  res.json({ cashedOut: true, winnings: winnings.toFixed(2), balance: totalBalance(users[username]), board: game.board });
});
app.post("/api/forfeit", requireAuth, (req, res) => {
  const { gameId } = req.body || {};
  const username = req.session.username;
  const game = games[gameId];
  if (!game || game.username !== username) return res.status(404).json({ error: "Jogo não encontrado" });
  if (game.finished) return res.status(400).json({ error: "Esse jogo já terminou" });
  game.finished = true;
  pushHistory(username, { result: "loss", bet: game.bet, bombs: game.bombs, boardSize: game.boardSize, multiplier: "0.00", payout: 0, at: new Date().toISOString() });
  res.json({ ok: true, board: game.board, balance: totalBalance(users[username]) });
});


setInterval(() => {
  const now = Date.now();
  for (const id in games) {
    if (games[id]._createdAt && now - games[id]._createdAt > 1000 * 60 * 30) delete games[id];
  }
}, 1000 * 60 * 10);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando em http://0.0.0.0:${PORT}`);
  if (!ADMIN_TOKEN) console.warn("Aviso: ADMIN_TOKEN não definido — painel de confirmação de Pix desativado.");
});