require("dotenv").config();

const express    = require("express");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const rateLimit  = require("express-rate-limit");
const helmet     = require("helmet");

const app = express();

// ====================== SEGURANÇA ======================
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: "5mb" })); // imagens base64 do perfil

// Rate limiting global
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: "Muitas requisições. Tente novamente em 15 minutos." },
});
app.use(limiter);

// Rate limiting mais restrito para auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { erro: "Muitas tentativas de login. Aguarde 15 minutos." },
});

// ====================== ENV CHECK ======================
const requiredEnvs = ["MONGO_URI", "JWT_SECRET"];
requiredEnvs.forEach(e => {
  if (!process.env[e]) { console.error(`❌ ${e} não definida`); process.exit(1); }
});

// ====================== DB CONNECTION ======================
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      maxPoolSize: 10,
    });
    console.log("✅ MongoDB conectado");
  } catch (err) {
    console.error("❌ erro MongoDB:", err.message);
    setTimeout(connectDB, 5000);
  }
}
connectDB();
mongoose.connection.on("disconnected", () => {
  console.warn("⚠️ MongoDB desconectado. Reconectando...");
  connectDB();
});

// ====================== SCHEMAS ======================

const usuarioSchema = new mongoose.Schema({
  nome:         { type: String, required: true, trim: true, maxlength: 120 },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 200 },
  senha:        { type: String, required: true },
  tipo_usuario: { type: String, enum: ["estudante", "empresa"], required: true },
  criado_em:    { type: Date, default: Date.now },
  ativo:        { type: Boolean, default: true },
});
usuarioSchema.index({ email: 1 });

// ── Estudante ──────────────────────────────────────────────
const projetoPortfolioSchema = new mongoose.Schema({
  nome:         { type: String, required: true, trim: true },
  descricao:    { type: String, default: "" },
  tecnologias:  { type: String, default: "" },
  link:         { type: String, default: "" },
  github:       { type: String, default: "" },
  criado_em:    { type: Date, default: Date.now },
}, { _id: true });

const estudanteSchema = new mongoose.Schema({
  usuario_id:  { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true, unique: true },
  telefone:    { type: String, default: "" },
  faculdade:   { type: String, default: "" },
  curso:       { type: String, default: "" },
  semestre:    { type: Number, default: null },
  cidade:      { type: String, default: "" },
  linkedin:    { type: String, default: "" },
  portfolio:   { type: String, default: "" },
  github:      { type: String, default: "" },
  areas:       { type: String, default: "" },
  bio:         { type: String, default: "", maxlength: 1000 },
  skills:      { type: [String], default: [] },
  foto:        { type: String, default: "" }, // base64 ou URL
  disponivel:  { type: Boolean, default: true },
  projetos_portfolio: { type: [projetoPortfolioSchema], default: [] },
  atualizado_em: { type: Date, default: Date.now },
});
estudanteSchema.index({ skills: 1 });
estudanteSchema.index({ cidade: 1 });
estudanteSchema.index({ disponivel: 1 });

// ── Empresa ────────────────────────────────────────────────
const empresaSchema = new mongoose.Schema({
  usuario_id:   { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true, unique: true },
  nome_empresa: { type: String, default: "" },
  responsavel:  { type: String, default: "" },
  telefone:     { type: String, default: "" },
  cnpj:         { type: String, default: "" },
  segmento:     { type: String, default: "" },
  tamanho:      { type: String, default: "" },
  foto:         { type: String, default: "" },
  atualizado_em: { type: Date, default: Date.now },
});

// ── Oportunidade ───────────────────────────────────────────
const oportunidadeSchema = new mongoose.Schema({
  empresa_id:  { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  titulo:      { type: String, required: true, trim: true, maxlength: 200 },
  descricao:   { type: String, required: true, maxlength: 3000 },
  escopo:      { type: String, default: "", maxlength: 3000 },
  responsavel: { type: String, default: "" },
  skills:      { type: [String], default: [] },
  prazo:       { type: String, default: "" },
  modalidade:  { type: String, enum: ["Remoto", "Presencial", "Híbrido"], default: "Remoto" },
  valor:       { type: String, default: "" },
  ativa:       { type: Boolean, default: true },
  criado_em:   { type: Date, default: Date.now },
});
oportunidadeSchema.index({ ativa: 1, criado_em: -1 });
oportunidadeSchema.index({ empresa_id: 1 });

// ── Candidatura ────────────────────────────────────────────
const candidaturaSchema = new mongoose.Schema({
  oportunidade_id: { type: mongoose.Schema.Types.ObjectId, ref: "Oportunidade", required: true },
  estudante_id:    { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  status: {
    type: String,
    enum: ["pendente", "visualizado", "em_andamento", "concluido", "recusado"],
    default: "pendente",
  },
  termo_aceito:      { type: Boolean, default: false },
  termo_aceito_em:   { type: Date, default: null },
  criado_em:         { type: Date, default: Date.now },
  atualizado_em:     { type: Date, default: Date.now },
});
candidaturaSchema.index({ oportunidade_id: 1, estudante_id: 1 }, { unique: true });
candidaturaSchema.index({ estudante_id: 1, status: 1 });

// ── Interesse empresa → estudante (BuscaTalentos) ──────────
// Separado de candidatura: a empresa demonstra interesse num estudante diretamente
const interesseSchema = new mongoose.Schema({
  empresa_id:   { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  estudante_id: { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  status:       { type: String, enum: ["pendente", "aceito", "recusado"], default: "pendente" },
  mensagem:     { type: String, default: "" },
  criado_em:    { type: Date, default: Date.now },
  atualizado_em: { type: Date, default: Date.now },
});
interesseSchema.index({ empresa_id: 1, estudante_id: 1 }, { unique: true });
interesseSchema.index({ estudante_id: 1, status: 1 });

// ── Avaliação ──────────────────────────────────────────────
const avaliacaoSchema = new mongoose.Schema({
  candidatura_id: { type: mongoose.Schema.Types.ObjectId, ref: "Candidatura", required: true },
  avaliador_id:   { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  avaliado_id:    { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  tipo:           { type: String, enum: ["empresa_avalia_estudante", "estudante_avalia_empresa"], required: true },
  ratings:        { type: Map, of: Number, default: {} }, // critérios individuais
  nota:           { type: Number, min: 1, max: 5, required: true },
  comentario:     { type: String, default: "" },
  criado_em:      { type: Date, default: Date.now },
});
avaliacaoSchema.index({ avaliado_id: 1 });
avaliacaoSchema.index({ candidatura_id: 1, avaliador_id: 1 }, { unique: true });

// ── Pesquisa de Satisfação ─────────────────────────────────
const pesquisaSchema = new mongoose.Schema({
  candidatura_id: { type: mongoose.Schema.Types.ObjectId, ref: "Candidatura", required: true, unique: true },
  empresa_id:     { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  respostas: {
    contratar:    { type: Number, min: 1, max: 5 },
    rapido:       { type: Number, min: 1, max: 5 },
    expectativas: { type: Number, min: 1, max: 5 },
  },
  criado_em: { type: Date, default: Date.now },
});

// ── Notificação ────────────────────────────────────────────
const notificacaoSchema = new mongoose.Schema({
  usuario_id: { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  icon:       { type: String, default: "🔔" },
  texto:      { type: String, required: true, maxlength: 300 },
  lida:       { type: Boolean, default: false },
  link:       { type: String, default: "" }, // rota do frontend
  criado_em:  { type: Date, default: Date.now },
});
notificacaoSchema.index({ usuario_id: 1, lida: 1, criado_em: -1 });

// ── Termo de Projeto ───────────────────────────────────────
const termoSchema = new mongoose.Schema({
  candidatura_id: { type: mongoose.Schema.Types.ObjectId, ref: "Candidatura", required: true, unique: true },
  empresa_id:     { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  estudante_id:   { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  aceito:         { type: Boolean, default: false },
  aceito_em:      { type: Date, default: null },
  dados: {
    titulo:      String,
    escopo:      String,
    prazo:       String,
    valor:       String,
    responsavel: String,
  },
  criado_em: { type: Date, default: Date.now },
});

// ── Models ─────────────────────────────────────────────────
const Usuario      = mongoose.model("Usuario",      usuarioSchema);
const Estudante    = mongoose.model("Estudante",    estudanteSchema);
const Empresa      = mongoose.model("Empresa",      empresaSchema);
const Oportunidade = mongoose.model("Oportunidade", oportunidadeSchema);
const Candidatura  = mongoose.model("Candidatura",  candidaturaSchema);
const Interesse    = mongoose.model("Interesse",    interesseSchema);
const Avaliacao    = mongoose.model("Avaliacao",    avaliacaoSchema);
const Pesquisa     = mongoose.model("Pesquisa",     pesquisaSchema);
const Notificacao  = mongoose.model("Notificacao",  notificacaoSchema);
const Termo        = mongoose.model("Termo",        termoSchema);

// ====================== HELPERS ======================

function sanitizeUser(user) {
  return {
    id: user._id,
    nome: user.nome,
    email: user.email,
    tipo_usuario: user.tipo_usuario,
    criado_em: user.criado_em,
  };
}

function generateToken(user) {
  return jwt.sign(
    { id: user._id, tipo_usuario: user.tipo_usuario },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Calcula média de notas de avaliações
function calcMedia(avaliacoes) {
  if (!avaliacoes.length) return null;
  return parseFloat(
    (avaliacoes.reduce((s, a) => s + a.nota, 0) / avaliacoes.length).toFixed(1)
  );
}

// Cria notificação de forma assíncrona sem bloquear a resposta
async function criarNotificacao(usuario_id, icon, texto, link = "") {
  try {
    await Notificacao.create({ usuario_id, icon, texto, link });
  } catch (err) {
    console.error("Erro ao criar notificação:", err.message);
  }
}

// Valida campos obrigatórios e retorna lista de faltantes
function validarCampos(body, campos) {
  return campos.filter(c => !body[c] || String(body[c]).trim() === "");
}

// ====================== MIDDLEWARES ======================

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer "))
    return res.status(401).json({ erro: "Token ausente ou mal formatado" });
  try {
    req.user = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch (err) {
    const msg = err.name === "TokenExpiredError" ? "Token expirado" : "Token inválido";
    return res.status(401).json({ erro: msg });
  }
}

function soEstudante(req, res, next) {
  if (req.user.tipo_usuario !== "estudante")
    return res.status(403).json({ erro: "Acesso restrito a estudantes" });
  next();
}

function soEmpresa(req, res, next) {
  if (req.user.tipo_usuario !== "empresa")
    return res.status(403).json({ erro: "Acesso restrito a empresas" });
  next();
}

// ====================== HEALTH ======================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    time: new Date().toISOString(),
    version: "2.0.0",
  });
});

// ====================== AUTH ======================

/**
 * POST /cadastro/estudante
 * Rota usada pelo frontend (CadEstudante)
 */
app.post("/cadastro/estudante", authLimiter, async (req, res) => {
  try {
    const { nome, email, senha, telefone, faculdade, curso, semestre,
            cidade, linkedin, portfolio, github, areas, bio, skills } = req.body;

    const faltantes = validarCampos(req.body, ["nome", "email", "senha"]);
    if (faltantes.length)
      return res.status(400).json({ erro: `Campos obrigatórios: ${faltantes.join(", ")}` });

    if (senha.length < 6)
      return res.status(400).json({ erro: "Senha deve ter ao menos 6 caracteres" });

    if (await Usuario.findOne({ email: email.toLowerCase().trim() }))
      return res.status(409).json({ erro: "E-mail já cadastrado" });

    const hash = await bcrypt.hash(senha, 12);
    const user = await Usuario.create({ nome: nome.trim(), email, senha: hash, tipo_usuario: "estudante" });

    await Estudante.create({
      usuario_id:  user._id,
      telefone:    telefone    || "",
      faculdade:   faculdade   || "",
      curso:       curso       || "",
      semestre:    semestre    ? parseInt(semestre) : null,
      cidade:      cidade      || "",
      linkedin:    linkedin    || "",
      portfolio:   portfolio   || "",
      github:      github      || "",
      areas:       areas       || "",
      bio:         bio         || "",
      skills:      Array.isArray(skills) ? skills : [],
    });

    // Notificação de boas-vindas
    await criarNotificacao(user._id, "🎉", "Bem-vindo ao RecrutÁgil! Complete seu perfil.", "perfil");

    res.status(201).json({ token: generateToken(user), usuario: sanitizeUser(user) });
  } catch (err) {
    console.error("cadastro-estudante:", err);
    res.status(500).json({ erro: "Erro interno ao cadastrar estudante" });
  }
});

/**
 * POST /cadastro/empresa
 * Rota usada pelo frontend (CadEmpresa)
 */
app.post("/cadastro/empresa", authLimiter, async (req, res) => {
  try {
    const { nome, responsavel, email, senha, telefone, cnpj, segmento, tamanho } = req.body;

    const faltantes = validarCampos(req.body, ["nome", "email", "senha"]);
    if (faltantes.length)
      return res.status(400).json({ erro: `Campos obrigatórios: ${faltantes.join(", ")}` });

    if (senha.length < 6)
      return res.status(400).json({ erro: "Senha deve ter ao menos 6 caracteres" });

    if (await Usuario.findOne({ email: email.toLowerCase().trim() }))
      return res.status(409).json({ erro: "E-mail já cadastrado" });

    const nomeUsuario = (responsavel || nome).trim();
    const hash = await bcrypt.hash(senha, 12);
    const user = await Usuario.create({ nome: nomeUsuario, email, senha: hash, tipo_usuario: "empresa" });

    await Empresa.create({
      usuario_id:   user._id,
      nome_empresa: nome.trim(),
      responsavel:  responsavel || "",
      telefone:     telefone    || "",
      cnpj:         cnpj        || "",
      segmento:     segmento    || "",
      tamanho:      tamanho     || "",
    });

    await criarNotificacao(user._id, "🏢", "Conta criada! Publique sua primeira vaga.", "publicar");

    res.status(201).json({ token: generateToken(user), usuario: sanitizeUser(user) });
  } catch (err) {
    console.error("cadastro-empresa:", err);
    res.status(500).json({ erro: "Erro interno ao cadastrar empresa" });
  }
});

// Aliases para compatibilidade (rotas antigas)
app.post("/auth/cadastro-estudante", authLimiter, (req, res) => {
  req.url = "/cadastro/estudante";
  app.handle(req, res);
});
app.post("/auth/cadastro-empresa", authLimiter, (req, res) => {
  req.url = "/cadastro/empresa";
  app.handle(req, res);
});

/**
 * POST /auth/login
 */
app.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha)
      return res.status(400).json({ erro: "E-mail e senha são obrigatórios" });

    const user = await Usuario.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(senha, user.senha)))
      return res.status(401).json({ erro: "E-mail ou senha inválidos" });

    if (!user.ativo)
      return res.status(403).json({ erro: "Conta desativada. Entre em contato com o suporte." });

    res.json({ token: generateToken(user), usuario: sanitizeUser(user) });
  } catch (err) {
    console.error("login:", err);
    res.status(500).json({ erro: "Erro no login" });
  }
});

/**
 * GET /me — dados completos do usuário logado (perfil + stats básicos)
 * Usado pelo frontend para hidratar o estado após reload
 */
app.get("/me", auth, async (req, res) => {
  try {
    const user = await Usuario.findById(req.user.id);
    if (!user || !user.ativo)
      return res.status(404).json({ erro: "Usuário não encontrado" });

    const perfil = req.user.tipo_usuario === "estudante"
      ? await Estudante.findOne({ usuario_id: user._id }).lean()
      : await Empresa.findOne({ usuario_id: user._id }).lean();

    res.json({ usuario: sanitizeUser(user), perfil: perfil || {} });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== PERFIL ESTUDANTE ======================

/** GET /estudante/perfil — perfil próprio */
app.get("/estudante/perfil", auth, soEstudante, async (req, res) => {
  try {
    const perfil = await Estudante.findOne({ usuario_id: req.user.id }).lean();
    if (!perfil) return res.status(404).json({ erro: "Perfil não encontrado" });
    res.json({ perfil });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** PUT /estudante/perfil — atualiza perfil (inclui foto base64 e portfolio de projetos) */
app.put("/estudante/perfil", auth, soEstudante, async (req, res) => {
  try {
    const camposPermitidos = [
      "telefone", "faculdade", "curso", "semestre", "cidade",
      "linkedin", "portfolio", "github", "areas", "bio",
      "skills", "disponivel", "foto",
    ];
    const update = {};
    camposPermitidos.forEach(c => {
      if (req.body[c] !== undefined) update[c] = req.body[c];
    });
    if (req.body.semestre) update.semestre = parseInt(req.body.semestre);
    update.atualizado_em = new Date();

    if (req.body.nome)
      await Usuario.findByIdAndUpdate(req.user.id, { nome: req.body.nome.trim() });

    const perfil = await Estudante.findOneAndUpdate(
      { usuario_id: req.user.id },
      { $set: update },
      { new: true, upsert: true }
    );
    res.json({ perfil });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** POST /estudante/perfil/projetos — adiciona projeto ao portfólio */
app.post("/estudante/perfil/projetos", auth, soEstudante, async (req, res) => {
  try {
    const { nome, descricao, tecnologias, link, github } = req.body;
    if (!nome) return res.status(400).json({ erro: "Nome do projeto é obrigatório" });

    const perfil = await Estudante.findOneAndUpdate(
      { usuario_id: req.user.id },
      { $push: { projetos_portfolio: { nome, descricao, tecnologias, link, github } } },
      { new: true }
    );
    res.status(201).json({ projetos: perfil.projetos_portfolio });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** DELETE /estudante/perfil/projetos/:projetoId — remove projeto do portfólio */
app.delete("/estudante/perfil/projetos/:projetoId", auth, soEstudante, async (req, res) => {
  try {
    const perfil = await Estudante.findOneAndUpdate(
      { usuario_id: req.user.id },
      { $pull: { projetos_portfolio: { _id: req.params.projetoId } } },
      { new: true }
    );
    res.json({ projetos: perfil.projetos_portfolio });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /estudante/:id — perfil público de um estudante */
app.get("/estudante/:id", auth, async (req, res) => {
  try {
    const user = await Usuario.findById(req.params.id);
    if (!user || user.tipo_usuario !== "estudante")
      return res.status(404).json({ erro: "Estudante não encontrado" });

    const perfil    = await Estudante.findOne({ usuario_id: req.params.id }).lean();
    const avaliacoes = await Avaliacao.find({ avaliado_id: req.params.id })
      .sort({ criado_em: -1 }).limit(10).lean();

    res.json({
      usuario:    sanitizeUser(user),
      perfil:     perfil || {},
      avaliacoes,
      media_nota: calcMedia(avaliacoes),
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== PERFIL EMPRESA ======================

app.get("/empresa/perfil", auth, soEmpresa, async (req, res) => {
  try {
    const perfil = await Empresa.findOne({ usuario_id: req.user.id }).lean();
    if (!perfil) return res.status(404).json({ erro: "Perfil não encontrado" });
    res.json({ perfil });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

app.put("/empresa/perfil", auth, soEmpresa, async (req, res) => {
  try {
    const campos = ["nome_empresa", "responsavel", "telefone", "cnpj", "segmento", "tamanho", "foto"];
    const update = {};
    campos.forEach(c => { if (req.body[c] !== undefined) update[c] = req.body[c]; });
    update.atualizado_em = new Date();

    if (req.body.nome)
      await Usuario.findByIdAndUpdate(req.user.id, { nome: req.body.nome.trim() });

    const perfil = await Empresa.findOneAndUpdate(
      { usuario_id: req.user.id },
      { $set: update },
      { new: true, upsert: true }
    );
    res.json({ perfil });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /empresa/:id — perfil público de uma empresa */
app.get("/empresa/:id", auth, async (req, res) => {
  try {
    const user = await Usuario.findById(req.params.id);
    if (!user || user.tipo_usuario !== "empresa")
      return res.status(404).json({ erro: "Empresa não encontrada" });

    const perfil = await Empresa.findOne({ usuario_id: req.params.id }).lean();
    const avaliacoes = await Avaliacao.find({ avaliado_id: req.params.id })
      .sort({ criado_em: -1 }).limit(10).lean();

    res.json({
      usuario:    sanitizeUser(user),
      perfil:     perfil || {},
      avaliacoes,
      media_nota: calcMedia(avaliacoes),
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== BUSCA DE TALENTOS ======================

/**
 * GET /talentos
 * Query: skill, cidade, faculdade, area, disponivel, page, limit
 * Retorna estudantes com média de avaliação incluída
 */
app.get("/talentos", auth, soEmpresa, async (req, res) => {
  try {
    const { skill, cidade, faculdade, area, page = 1, limit = 12 } = req.query;

    const filtro = { disponivel: true };
    if (skill)     filtro.skills    = { $regex: skill, $options: "i" };
    if (cidade)    filtro.cidade    = { $regex: cidade, $options: "i" };
    if (faculdade) filtro.faculdade = { $regex: faculdade, $options: "i" };
    if (area)      filtro.areas     = { $regex: area, $options: "i" };

    const skip  = (parseInt(page) - 1) * parseInt(limit);
    const total = await Estudante.countDocuments(filtro);
    const perfis = await Estudante.find(filtro)
      .skip(skip).limit(parseInt(limit)).lean();

    // Enriquecer com dados do usuário
    const ids      = perfis.map(p => p.usuario_id);
    const usuarios = await Usuario.find({ _id: { $in: ids } }).lean();
    const usuMap   = Object.fromEntries(usuarios.map(u => [String(u._id), u]));

    // Buscar médias de avaliação em batch
    const medias = await Avaliacao.aggregate([
      { $match: { avaliado_id: { $in: ids } } },
      { $group: { _id: "$avaliado_id", media: { $avg: "$nota" }, total: { $sum: 1 } } },
    ]);
    const mediaMap = Object.fromEntries(
      medias.map(m => [String(m._id), { media: parseFloat(m.media.toFixed(1)), total: m.total }])
    );

    // Verificar se já foi enviado interesse para cada estudante
    const interessesEnviados = await Interesse.find({
      empresa_id: req.user.id,
      estudante_id: { $in: ids },
    }).lean();
    const interesseMap = Object.fromEntries(
      interessesEnviados.map(i => [String(i.estudante_id), i.status])
    );

    const resultado = perfis.map(p => ({
      ...p,
      nome:             usuMap[String(p.usuario_id)]?.nome || "",
      email:            usuMap[String(p.usuario_id)]?.email || "",
      media_nota:       mediaMap[String(p.usuario_id)]?.media || null,
      total_avaliacoes: mediaMap[String(p.usuario_id)]?.total || 0,
      interesse_status: interesseMap[String(p.usuario_id)] || null,
    }));

    res.json({ total, pagina: parseInt(page), limit: parseInt(limit), estudantes: resultado });
  } catch (err) {
    console.error("talentos:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== INTERESSES (empresa → estudante) ======================

/**
 * POST /interesses
 * Empresa demonstra interesse num estudante diretamente (BuscaTalentos)
 * Body: { estudante_id, mensagem? }
 */
app.post("/interesses", auth, soEmpresa, async (req, res) => {
  try {
    const { estudante_id, mensagem } = req.body;
    if (!estudante_id)
      return res.status(400).json({ erro: "estudante_id é obrigatório" });

    const estudante = await Usuario.findById(estudante_id);
    if (!estudante || estudante.tipo_usuario !== "estudante")
      return res.status(404).json({ erro: "Estudante não encontrado" });

    const empPerfil = await Empresa.findOne({ usuario_id: req.user.id }).lean();
    const nomeEmpresa = empPerfil?.nome_empresa || "Uma empresa";

    const interesse = await Interesse.create({
      empresa_id:   req.user.id,
      estudante_id,
      mensagem:     mensagem || "",
    });

    // Notifica o estudante
    await criarNotificacao(
      estudante_id,
      "💌",
      `${nomeEmpresa} demonstrou interesse no seu perfil!`,
      "dashboard"
    );

    res.status(201).json({ interesse });
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ erro: "Interesse já enviado para este estudante" });
    console.error("interesse:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * GET /interesses/recebidos — estudante vê interesses recebidos de empresas
 */
app.get("/interesses/recebidos", auth, soEstudante, async (req, res) => {
  try {
    const interesses = await Interesse.find({ estudante_id: req.user.id })
      .sort({ criado_em: -1 }).lean();

    const empIds   = interesses.map(i => i.empresa_id);
    const empresas = await Empresa.find({ usuario_id: { $in: empIds } }).lean();
    const usuarios = await Usuario.find({ _id: { $in: empIds } }).lean();
    const empPerfilMap = Object.fromEntries(empresas.map(e => [String(e.usuario_id), e]));
    const usuMap       = Object.fromEntries(usuarios.map(u => [String(u._id), u]));

    const resultado = interesses.map(i => ({
      ...i,
      empresa: {
        id:           i.empresa_id,
        nome:         usuMap[String(i.empresa_id)]?.nome || "",
        nome_empresa: empPerfilMap[String(i.empresa_id)]?.nome_empresa || "",
        segmento:     empPerfilMap[String(i.empresa_id)]?.segmento || "",
        foto:         empPerfilMap[String(i.empresa_id)]?.foto || "",
      },
    }));

    res.json({ total: resultado.length, interesses: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * PATCH /interesses/:id/responder
 * Estudante aceita ou recusa interesse de empresa
 * Body: { status: "aceito" | "recusado" }
 */
app.patch("/interesses/:id/responder", auth, soEstudante, async (req, res) => {
  try {
    const { status } = req.body;
    if (!["aceito", "recusado"].includes(status))
      return res.status(400).json({ erro: 'status deve ser "aceito" ou "recusado"' });

    const interesse = await Interesse.findOne({
      _id: req.params.id,
      estudante_id: req.user.id,
    });
    if (!interesse)
      return res.status(404).json({ erro: "Interesse não encontrado" });

    interesse.status       = status;
    interesse.atualizado_em = new Date();
    await interesse.save();

    // Notifica a empresa
    const estudante = await Usuario.findById(req.user.id);
    const nomeAcao  = status === "aceito" ? "aceitou" : "recusou";
    await criarNotificacao(
      interesse.empresa_id,
      status === "aceito" ? "✅" : "❌",
      `${estudante.nome} ${nomeAcao} seu interesse.`,
      "talentos"
    );

    res.json({ interesse });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /interesses/enviados — empresa vê interesses que enviou */
app.get("/interesses/enviados", auth, soEmpresa, async (req, res) => {
  try {
    const interesses = await Interesse.find({ empresa_id: req.user.id })
      .sort({ criado_em: -1 }).lean();

    const estIds   = interesses.map(i => i.estudante_id);
    const perfis   = await Estudante.find({ usuario_id: { $in: estIds } }).lean();
    const usuarios = await Usuario.find({ _id: { $in: estIds } }).lean();
    const perfMap  = Object.fromEntries(perfis.map(p => [String(p.usuario_id), p]));
    const usuMap   = Object.fromEntries(usuarios.map(u => [String(u._id), u]));

    const resultado = interesses.map(i => ({
      ...i,
      estudante: {
        id:        i.estudante_id,
        nome:      usuMap[String(i.estudante_id)]?.nome || "",
        faculdade: perfMap[String(i.estudante_id)]?.faculdade || "",
        curso:     perfMap[String(i.estudante_id)]?.curso || "",
        skills:    perfMap[String(i.estudante_id)]?.skills || [],
        foto:      perfMap[String(i.estudante_id)]?.foto || "",
      },
    }));

    res.json({ total: resultado.length, interesses: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== OPORTUNIDADES ======================

/** POST /oportunidades — empresa publica vaga */
app.post("/oportunidades", auth, soEmpresa, async (req, res) => {
  try {
    const { titulo, descricao, escopo, responsavel, skills, prazo, modalidade, valor } = req.body;
    const faltantes = validarCampos(req.body, ["titulo", "descricao"]);
    if (faltantes.length)
      return res.status(400).json({ erro: `Campos obrigatórios: ${faltantes.join(", ")}` });

    const op = await Oportunidade.create({
      empresa_id:  req.user.id,
      titulo:      titulo.trim(),
      descricao,
      escopo:      escopo      || "",
      responsavel: responsavel || "",
      skills:      Array.isArray(skills) ? skills : [],
      prazo:       prazo       || "",
      modalidade:  modalidade  || "Remoto",
      valor:       valor       || "",
    });

    res.status(201).json({ oportunidade: op });
  } catch (err) {
    console.error("criar oportunidade:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * GET /oportunidades
 * Query: skill, modalidade, page, limit
 * Pública para usuários autenticados
 */
app.get("/oportunidades", auth, async (req, res) => {
  try {
    const { skill, modalidade, page = 1, limit = 10 } = req.query;
    const filtro = { ativa: true };
    if (skill)      filtro.skills     = { $regex: skill, $options: "i" };
    if (modalidade) filtro.modalidade = modalidade;

    const skip  = (parseInt(page) - 1) * parseInt(limit);
    const total = await Oportunidade.countDocuments(filtro);
    const ops   = await Oportunidade.find(filtro)
      .sort({ criado_em: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Enriquecer com nome da empresa
    const empIds  = ops.map(o => o.empresa_id);
    const empresas = await Empresa.find({ usuario_id: { $in: empIds } }).lean();
    const empMap  = Object.fromEntries(empresas.map(e => [String(e.usuario_id), e]));

    // Se for estudante, marcar quais já demonstrou interesse
    let interesseMap = {};
    if (req.user.tipo_usuario === "estudante") {
      const opIds = ops.map(o => o._id);
      const cands = await Candidatura.find({
        estudante_id:    req.user.id,
        oportunidade_id: { $in: opIds },
      }).lean();
      interesseMap = Object.fromEntries(
        cands.map(c => [String(c.oportunidade_id), c.status])
      );
    }

    const resultado = ops.map(o => ({
      ...o,
      nome_empresa:     empMap[String(o.empresa_id)]?.nome_empresa || "",
      interesse_status: interesseMap[String(o._id)] || null,
    }));

    res.json({ total, pagina: parseInt(page), limit: parseInt(limit), oportunidades: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /oportunidades/minhas — vagas da empresa logada */
app.get("/oportunidades/minhas", auth, soEmpresa, async (req, res) => {
  try {
    const ops = await Oportunidade.find({ empresa_id: req.user.id })
      .sort({ criado_em: -1 }).lean();

    // Contar candidatos por vaga em batch
    const opIds = ops.map(o => o._id);
    const contagens = await Candidatura.aggregate([
      { $match: { oportunidade_id: { $in: opIds } } },
      { $group: { _id: "$oportunidade_id", total: { $sum: 1 } } },
    ]);
    const contagemMap = Object.fromEntries(contagens.map(c => [String(c._id), c.total]));

    const resultado = ops.map(o => ({
      ...o,
      total_candidatos: contagemMap[String(o._id)] || 0,
    }));

    res.json({ total: resultado.length, oportunidades: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /oportunidades/:id — detalhe */
app.get("/oportunidades/:id", auth, async (req, res) => {
  try {
    const op = await Oportunidade.findById(req.params.id).lean();
    if (!op) return res.status(404).json({ erro: "Oportunidade não encontrada" });

    const emp = await Empresa.findOne({ usuario_id: op.empresa_id }).lean();
    res.json({ oportunidade: { ...op, nome_empresa: emp?.nome_empresa || "" } });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** PUT /oportunidades/:id — editar */
app.put("/oportunidades/:id", auth, soEmpresa, async (req, res) => {
  try {
    const op = await Oportunidade.findOne({ _id: req.params.id, empresa_id: req.user.id });
    if (!op) return res.status(404).json({ erro: "Não encontrada ou sem permissão" });

    const campos = ["titulo", "descricao", "escopo", "responsavel", "skills", "prazo", "modalidade", "valor", "ativa"];
    campos.forEach(c => { if (req.body[c] !== undefined) op[c] = req.body[c]; });
    await op.save();
    res.json({ oportunidade: op });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** DELETE /oportunidades/:id — encerrar vaga */
app.delete("/oportunidades/:id", auth, soEmpresa, async (req, res) => {
  try {
    const op = await Oportunidade.findOneAndUpdate(
      { _id: req.params.id, empresa_id: req.user.id },
      { ativa: false },
      { new: true }
    );
    if (!op) return res.status(404).json({ erro: "Não encontrada ou sem permissão" });
    res.json({ mensagem: "Oportunidade encerrada", oportunidade: op });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== CANDIDATURAS ======================

/**
 * POST /oportunidades/:id/interesse
 * Estudante demonstra interesse numa vaga
 */
app.post("/oportunidades/:id/interesse", auth, soEstudante, async (req, res) => {
  try {
    const op = await Oportunidade.findById(req.params.id);
    if (!op || !op.ativa)
      return res.status(404).json({ erro: "Oportunidade não disponível" });

    const candidatura = await Candidatura.create({
      oportunidade_id: op._id,
      estudante_id:    req.user.id,
    });

    // Notifica a empresa
    const estudante   = await Usuario.findById(req.user.id);
    const empPerfil   = await Empresa.findOne({ usuario_id: op.empresa_id }).lean();
    await criarNotificacao(
      op.empresa_id,
      "💌",
      `${estudante.nome} demonstrou interesse em "${op.titulo}"`,
      "projetos"
    );

    res.status(201).json({ mensagem: "Interesse registrado!", candidatura });
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ erro: "Você já demonstrou interesse nesta vaga" });
    console.error("interesse vaga:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /oportunidades/:id/candidatos — empresa vê candidatos */
app.get("/oportunidades/:id/candidatos", auth, soEmpresa, async (req, res) => {
  try {
    const op = await Oportunidade.findOne({ _id: req.params.id, empresa_id: req.user.id });
    if (!op) return res.status(404).json({ erro: "Não encontrada ou sem permissão" });

    const candidaturas = await Candidatura.find({ oportunidade_id: op._id })
      .sort({ criado_em: -1 }).lean();

    const ids      = candidaturas.map(c => c.estudante_id);
    const usuarios = await Usuario.find({ _id: { $in: ids } }).lean();
    const perfis   = await Estudante.find({ usuario_id: { $in: ids } }).lean();

    const usuMap  = Object.fromEntries(usuarios.map(u => [String(u._id), u]));
    const perfMap = Object.fromEntries(perfis.map(p => [String(p.usuario_id), p]));

    // Médias de avaliação em batch
    const medias = await Avaliacao.aggregate([
      { $match: { avaliado_id: { $in: ids } } },
      { $group: { _id: "$avaliado_id", media: { $avg: "$nota" } } },
    ]);
    const mediaMap = Object.fromEntries(
      medias.map(m => [String(m._id), parseFloat(m.media.toFixed(1))])
    );

    const resultado = candidaturas.map(c => ({
      candidatura_id: c._id,
      status:         c.status,
      criado_em:      c.criado_em,
      termo_aceito:   c.termo_aceito,
      estudante: {
        id:         c.estudante_id,
        nome:       usuMap[String(c.estudante_id)]?.nome || "",
        email:      usuMap[String(c.estudante_id)]?.email || "",
        faculdade:  perfMap[String(c.estudante_id)]?.faculdade || "",
        curso:      perfMap[String(c.estudante_id)]?.curso || "",
        semestre:   perfMap[String(c.estudante_id)]?.semestre || null,
        cidade:     perfMap[String(c.estudante_id)]?.cidade || "",
        skills:     perfMap[String(c.estudante_id)]?.skills || [],
        linkedin:   perfMap[String(c.estudante_id)]?.linkedin || "",
        portfolio:  perfMap[String(c.estudante_id)]?.portfolio || "",
        github:     perfMap[String(c.estudante_id)]?.github || "",
        bio:        perfMap[String(c.estudante_id)]?.bio || "",
        foto:       perfMap[String(c.estudante_id)]?.foto || "",
        media_nota: mediaMap[String(c.estudante_id)] || null,
      },
    }));

    res.json({ total: resultado.length, candidatos: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * PUT /candidaturas/:id/status
 * Body: { status: "em_andamento" | "concluido" | "recusado" | "visualizado" }
 */
app.put("/candidaturas/:id/status", auth, soEmpresa, async (req, res) => {
  try {
    const { status } = req.body;
    const validos = ["pendente", "visualizado", "em_andamento", "concluido", "recusado"];
    if (!validos.includes(status))
      return res.status(400).json({ erro: `Status inválido. Use: ${validos.join(", ")}` });

    const candidatura = await Candidatura.findById(req.params.id).populate("oportunidade_id");
    if (!candidatura) return res.status(404).json({ erro: "Candidatura não encontrada" });

    if (String(candidatura.oportunidade_id.empresa_id) !== String(req.user.id))
      return res.status(403).json({ erro: "Sem permissão" });

    candidatura.status        = status;
    candidatura.atualizado_em = new Date();
    await candidatura.save();

    // Notifica o estudante
    const notifMap = {
      em_andamento: { icon: "🚀", texto: `Projeto "${candidatura.oportunidade_id.titulo}" foi iniciado! Bom trabalho.` },
      concluido:    { icon: "🏆", texto: `Projeto "${candidatura.oportunidade_id.titulo}" concluído! Deixe sua avaliação.` },
      recusado:     { icon: "❌", texto: `Sua candidatura para "${candidatura.oportunidade_id.titulo}" não foi selecionada.` },
      visualizado:  { icon: "👀", texto: `Sua candidatura para "${candidatura.oportunidade_id.titulo}" foi visualizada.` },
    };
    if (notifMap[status]) {
      await criarNotificacao(
        candidatura.estudante_id,
        notifMap[status].icon,
        notifMap[status].texto,
        "dashboard"
      );
    }

    res.json({ candidatura });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /candidaturas/minhas — estudante vê suas candidaturas */
app.get("/candidaturas/minhas", auth, soEstudante, async (req, res) => {
  try {
    const candidaturas = await Candidatura.find({ estudante_id: req.user.id })
      .sort({ criado_em: -1 }).lean();

    const opIds    = candidaturas.map(c => c.oportunidade_id);
    const ops      = await Oportunidade.find({ _id: { $in: opIds } }).lean();
    const opMap    = Object.fromEntries(ops.map(o => [String(o._id), o]));

    const empIds   = ops.map(o => o.empresa_id);
    const empresas = await Empresa.find({ usuario_id: { $in: empIds } }).lean();
    const empMap   = Object.fromEntries(empresas.map(e => [String(e.usuario_id), e]));

    const resultado = candidaturas.map(c => ({
      candidatura_id: c._id,
      status:         c.status,
      criado_em:      c.criado_em,
      termo_aceito:   c.termo_aceito,
      oportunidade: {
        id:           opMap[String(c.oportunidade_id)]?._id,
        titulo:       opMap[String(c.oportunidade_id)]?.titulo || "",
        skills:       opMap[String(c.oportunidade_id)]?.skills || [],
        modalidade:   opMap[String(c.oportunidade_id)]?.modalidade || "",
        valor:        opMap[String(c.oportunidade_id)]?.valor || "",
        prazo:        opMap[String(c.oportunidade_id)]?.prazo || "",
        nome_empresa: empMap[String(opMap[String(c.oportunidade_id)]?.empresa_id)]?.nome_empresa || "",
      },
    }));

    res.json({ candidaturas: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== TERMOS DE PROJETO ======================

/**
 * POST /termos
 * Empresa cria o termo ao publicar a vaga (ou ao iniciar)
 * Body: { candidatura_id, titulo, escopo, prazo, valor, responsavel }
 */
app.post("/termos", auth, soEmpresa, async (req, res) => {
  try {
    const { candidatura_id, titulo, escopo, prazo, valor, responsavel } = req.body;
    if (!candidatura_id)
      return res.status(400).json({ erro: "candidatura_id é obrigatório" });

    const candidatura = await Candidatura.findById(candidatura_id).populate("oportunidade_id");
    if (!candidatura) return res.status(404).json({ erro: "Candidatura não encontrada" });

    if (String(candidatura.oportunidade_id.empresa_id) !== String(req.user.id))
      return res.status(403).json({ erro: "Sem permissão" });

    const termo = await Termo.findOneAndUpdate(
      { candidatura_id },
      {
        empresa_id:   req.user.id,
        estudante_id: candidatura.estudante_id,
        dados:        { titulo, escopo, prazo, valor, responsavel },
        aceito:       false,
        aceito_em:    null,
      },
      { upsert: true, new: true }
    );

    // Notifica o estudante
    await criarNotificacao(
      candidatura.estudante_id,
      "📄",
      `Termo de projeto disponível: "${titulo || candidatura.oportunidade_id.titulo}". Aceite para iniciar.`,
      "dashboard"
    );

    res.status(201).json({ termo });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * POST /termos/:id/aceitar
 * Estudante aceita o termo
 */
app.post("/termos/:id/aceitar", auth, soEstudante, async (req, res) => {
  try {
    const termo = await Termo.findOne({
      _id:         req.params.id,
      estudante_id: req.user.id,
      aceito:      false,
    });
    if (!termo) return res.status(404).json({ erro: "Termo não encontrado ou já aceito" });

    termo.aceito    = true;
    termo.aceito_em = new Date();
    await termo.save();

    // Atualiza candidatura
    await Candidatura.findByIdAndUpdate(termo.candidatura_id, {
      termo_aceito:    true,
      termo_aceito_em: new Date(),
    });

    // Notifica empresa
    const estudante = await Usuario.findById(req.user.id);
    await criarNotificacao(
      termo.empresa_id,
      "✅",
      `${estudante.nome} aceitou o termo e o projeto foi iniciado!`,
      "projetos"
    );

    res.json({ termo });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /termos/candidatura/:candidatura_id — busca termo de uma candidatura */
app.get("/termos/candidatura/:candidatura_id", auth, async (req, res) => {
  try {
    const termo = await Termo.findOne({ candidatura_id: req.params.candidatura_id });
    if (!termo) return res.status(404).json({ erro: "Termo não encontrado" });

    // Verifica permissão (empresa dona ou estudante do termo)
    const pertence =
      String(termo.empresa_id) === String(req.user.id) ||
      String(termo.estudante_id) === String(req.user.id);
    if (!pertence) return res.status(403).json({ erro: "Sem permissão" });

    res.json({ termo });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== AVALIAÇÕES ======================

/**
 * POST /avaliacoes
 * Body: { candidatura_id, nota, comentario, ratings? }
 */
app.post("/avaliacoes", auth, async (req, res) => {
  try {
    const { candidatura_id, nota, comentario, ratings } = req.body;
    if (!candidatura_id || nota == null)
      return res.status(400).json({ erro: "candidatura_id e nota são obrigatórios" });

    if (nota < 1 || nota > 5)
      return res.status(400).json({ erro: "Nota deve ser entre 1 e 5" });

    const candidatura = await Candidatura.findById(candidatura_id).populate("oportunidade_id");
    if (!candidatura) return res.status(404).json({ erro: "Candidatura não encontrada" });
    if (candidatura.status !== "concluido")
      return res.status(400).json({ erro: "Só é possível avaliar projetos concluídos" });

    const eh_empresa   = String(candidatura.oportunidade_id.empresa_id) === String(req.user.id);
    const eh_estudante = String(candidatura.estudante_id) === String(req.user.id);
    if (!eh_empresa && !eh_estudante)
      return res.status(403).json({ erro: "Sem permissão para avaliar" });

    const avaliado_id = eh_empresa
      ? candidatura.estudante_id
      : candidatura.oportunidade_id.empresa_id;

    const tipo = eh_empresa ? "empresa_avalia_estudante" : "estudante_avalia_empresa";

    const avaliacao = await Avaliacao.create({
      candidatura_id,
      avaliador_id: req.user.id,
      avaliado_id,
      tipo,
      nota,
      ratings:    ratings   || {},
      comentario: comentario || "",
    });

    // Notifica quem foi avaliado
    const avaliador = await Usuario.findById(req.user.id);
    await criarNotificacao(
      avaliado_id,
      "⭐",
      `${avaliador.nome} deixou uma avaliação ${nota}/5 para você.`,
      "dashboard"
    );

    res.status(201).json({ avaliacao });
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ erro: "Você já avaliou este projeto" });
    console.error("avaliacao:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

/** GET /avaliacoes/:usuario_id — avaliações recebidas por um usuário */
app.get("/avaliacoes/:usuario_id", auth, async (req, res) => {
  try {
    const avaliacoes = await Avaliacao.find({ avaliado_id: req.params.usuario_id })
      .sort({ criado_em: -1 }).lean();

    res.json({
      total:      avaliacoes.length,
      media_nota: calcMedia(avaliacoes),
      avaliacoes,
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== PESQUISA DE SATISFAÇÃO ======================

/**
 * POST /pesquisas
 * Body: { candidatura_id, respostas: { contratar, rapido, expectativas } }
 */
app.post("/pesquisas", auth, soEmpresa, async (req, res) => {
  try {
    const { candidatura_id, respostas } = req.body;
    if (!candidatura_id)
      return res.status(400).json({ erro: "candidatura_id é obrigatório" });

    const candidatura = await Candidatura.findById(candidatura_id).populate("oportunidade_id");
    if (!candidatura) return res.status(404).json({ erro: "Candidatura não encontrada" });

    if (String(candidatura.oportunidade_id.empresa_id) !== String(req.user.id))
      return res.status(403).json({ erro: "Sem permissão" });

    const pesquisa = await Pesquisa.findOneAndUpdate(
      { candidatura_id },
      { empresa_id: req.user.id, respostas: respostas || {} },
      { upsert: true, new: true }
    );

    res.status(201).json({ pesquisa });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== NOTIFICAÇÕES ======================

/**
 * GET /notificacoes
 * Query: page, limit, lidas (true|false)
 */
app.get("/notificacoes", auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, lidas } = req.query;
    const filtro = { usuario_id: req.user.id };
    if (lidas === "false") filtro.lida = false;
    if (lidas === "true")  filtro.lida = true;

    const skip  = (parseInt(page) - 1) * parseInt(limit);
    const total = await Notificacao.countDocuments(filtro);
    const nao_lidas = await Notificacao.countDocuments({ usuario_id: req.user.id, lida: false });
    const notifs = await Notificacao.find(filtro)
      .sort({ criado_em: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    res.json({ total, nao_lidas, pagina: parseInt(page), notificacoes: notifs });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * PATCH /notificacoes/marcar-lidas
 * Marca todas as notificações do usuário como lidas
 */
app.patch("/notificacoes/marcar-lidas", auth, async (req, res) => {
  try {
    await Notificacao.updateMany(
      { usuario_id: req.user.id, lida: false },
      { $set: { lida: true } }
    );
    res.json({ mensagem: "Notificações marcadas como lidas" });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * PATCH /notificacoes/:id/ler
 * Marca uma notificação específica como lida
 */
app.patch("/notificacoes/:id/ler", auth, async (req, res) => {
  try {
    const notif = await Notificacao.findOneAndUpdate(
      { _id: req.params.id, usuario_id: req.user.id },
      { $set: { lida: true } },
      { new: true }
    );
    if (!notif) return res.status(404).json({ erro: "Notificação não encontrada" });
    res.json({ notificacao: notif });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== STATS ======================

/**
 * GET /stats
 * Dashboard: empresa vê stats das suas vagas; estudante vê stats pessoais
 */
app.get("/stats", auth, async (req, res) => {
  try {
    if (req.user.tipo_usuario === "empresa") {
      const ops    = await Oportunidade.find({ empresa_id: req.user.id }).lean();
      const opIds  = ops.map(o => o._id);

      const [candidatos, ativos, concluidos, interesses] = await Promise.all([
        Candidatura.countDocuments({ oportunidade_id: { $in: opIds } }),
        Candidatura.countDocuments({ oportunidade_id: { $in: opIds }, status: "em_andamento" }),
        Candidatura.countDocuments({ oportunidade_id: { $in: opIds }, status: "concluido" }),
        Interesse.countDocuments({ empresa_id: req.user.id }),
      ]);

      const avaliacoes = await Avaliacao.find({ avaliado_id: req.user.id }).lean();

      return res.json({
        vagas_publicadas:   ops.length,
        vagas_ativas:       ops.filter(o => o.ativa).length,
        total_candidatos:   candidatos,
        projetos_ativos:    ativos,
        projetos_concluidos: concluidos,
        interesses_enviados: interesses,
        media_nota:         calcMedia(avaliacoes),
        total_avaliacoes:   avaliacoes.length,
      });
    }

    // Estudante
    const candidaturas = await Candidatura.find({ estudante_id: req.user.id }).lean();
    const avaliacoes   = await Avaliacao.find({ avaliado_id: req.user.id }).lean();
    const interesses   = await Interesse.find({ estudante_id: req.user.id }).lean();
    const perfil       = await Estudante.findOne({ usuario_id: req.user.id }).lean();

    const totalOps = await Oportunidade.countDocuments({ ativa: true });

    res.json({
      oportunidades_abertas:  totalOps,
      interesses_enviados:    candidaturas.length,
      interesses_recebidos:   interesses.length,
      projetos_concluidos:    candidaturas.filter(c => c.status === "concluido").length,
      projetos_ativos:        candidaturas.filter(c => c.status === "em_andamento").length,
      media_nota:             calcMedia(avaliacoes),
      total_avaliacoes:       avaliacoes.length,
      projetos_portfolio:     perfil?.projetos_portfolio?.length || 0,
    });
  } catch (err) {
    console.error("stats:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

/**
 * GET /stats/plataforma
 * Métricas globais (tela Metricas do frontend — visível a empresas)
 */
app.get("/stats/plataforma", auth, soEmpresa, async (req, res) => {
  try {
    const [
      totalEmpresas,
      totalEstudantes,
      totalVagas,
      totalCandidaturas,
      totalConcluidos,
      totalAtivos,
    ] = await Promise.all([
      Usuario.countDocuments({ tipo_usuario: "empresa" }),
      Usuario.countDocuments({ tipo_usuario: "estudante" }),
      Oportunidade.countDocuments(),
      Candidatura.countDocuments(),
      Candidatura.countDocuments({ status: "concluido" }),
      Candidatura.countDocuments({ status: "em_andamento" }),
    ]);

    const pesquisas  = await Pesquisa.find().lean();
    const recontratarMedia = pesquisas.length
      ? (pesquisas.reduce((s, p) => s + (p.respostas?.contratar || 0), 0) / pesquisas.length).toFixed(1)
      : null;

    const avaliacoes = await Avaliacao.find().lean();

    res.json({
      empresas_cadastradas: totalEmpresas,
      estudantes_cadastrados: totalEstudantes,
      vagas_publicadas:       totalVagas,
      total_candidaturas:     totalCandidaturas,
      projetos_concluidos:    totalConcluidos,
      projetos_ativos:        totalAtivos,
      media_nota_plataforma:  calcMedia(avaliacoes),
      taxa_recontratar:       recontratarMedia,
      // Critérios fase 2
      fase2: {
        empresas:    { atual: totalEmpresas,   meta: 10 },
        estudantes:  { atual: totalEstudantes, meta: 50 },
        concluidos:  { atual: totalConcluidos, meta: 5 },
        nota:        { atual: calcMedia(avaliacoes), meta: 4 },
      },
    });
  } catch (err) {
    console.error("stats/plataforma:", err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== 404 / ERROR HANDLER ======================

app.use((req, res) => {
  res.status(404).json({ erro: `Rota não encontrada: ${req.method} ${req.path}` });
});

app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  res.status(500).json({ erro: "Erro interno do servidor" });
});

// ====================== START ======================

const PORT = parseInt(process.env.PORT) || 10000;
app.listen(PORT, () => console.log(`🚀 RecrutÁgil v2 rodando na porta ${PORT}`));
