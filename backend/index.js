require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cors());

// ====================== ENV CHECK ======================
if (!process.env.MONGO_URI) { console.error("❌ MONGO_URI não definida"); process.exit(1); }
if (!process.env.JWT_SECRET) { console.error("❌ JWT_SECRET não definida"); process.exit(1); }

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
  console.warn("⚠️ MongoDB caiu, reconectando...");
  connectDB();
});

// ====================== SCHEMAS ======================

const usuarioSchema = new mongoose.Schema({
  nome:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  senha:        { type: String, required: true },
  tipo_usuario: { type: String, enum: ["estudante", "empresa"], required: true },
  criado_em:    { type: Date, default: Date.now },
});

// Perfil detalhado do estudante
const estudanteSchema = new mongoose.Schema({
  usuario_id:  { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true, unique: true },
  telefone:    { type: String, default: "" },
  faculdade:   { type: String, default: "" },
  curso:       { type: String, default: "" },
  semestre:    { type: Number, default: null },
  cidade:      { type: String, default: "" },
  linkedin:    { type: String, default: "" },
  portfolio:   { type: String, default: "" },
  areas:       { type: String, default: "" },
  bio:         { type: String, default: "" },
  skills:      { type: [String], default: [] },
  disponivel:  { type: Boolean, default: true },
  atualizado_em: { type: Date, default: Date.now },
});

// Perfil detalhado da empresa
const empresaSchema = new mongoose.Schema({
  usuario_id:   { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true, unique: true },
  nome_empresa: { type: String, default: "" },
  responsavel:  { type: String, default: "" },
  telefone:     { type: String, default: "" },
  segmento:     { type: String, default: "" },
  tamanho:      { type: String, default: "" },
  atualizado_em: { type: Date, default: Date.now },
});

// Oportunidade publicada pela empresa
const oportunidadeSchema = new mongoose.Schema({
  empresa_id:  { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  titulo:      { type: String, required: true, trim: true },
  descricao:   { type: String, required: true },
  skills:      { type: [String], default: [] },
  prazo:       { type: String, default: "" },
  modalidade:  { type: String, enum: ["Remoto", "Presencial", "Híbrido"], default: "Remoto" },
  valor:       { type: String, default: "" },
  ativa:       { type: Boolean, default: true },
  criado_em:   { type: Date, default: Date.now },
});

// Candidatura / demonstração de interesse
const candidaturaSchema = new mongoose.Schema({
  oportunidade_id: { type: mongoose.Schema.Types.ObjectId, ref: "Oportunidade", required: true },
  estudante_id:    { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  status:          { type: String, enum: ["pendente", "visualizado", "em_andamento", "concluido", "recusado"], default: "pendente" },
  criado_em:       { type: Date, default: Date.now },
  atualizado_em:   { type: Date, default: Date.now },
});
// Impede candidatura duplicada
candidaturaSchema.index({ oportunidade_id: 1, estudante_id: 1 }, { unique: true });

// Avaliação pós-projeto
const avaliacaoSchema = new mongoose.Schema({
  candidatura_id: { type: mongoose.Schema.Types.ObjectId, ref: "Candidatura", required: true },
  avaliador_id:   { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  avaliado_id:    { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
  nota:           { type: Number, min: 1, max: 5, required: true },
  comentario:     { type: String, default: "" },
  criado_em:      { type: Date, default: Date.now },
});

const Usuario     = mongoose.model("Usuario",     usuarioSchema);
const Estudante   = mongoose.model("Estudante",   estudanteSchema);
const Empresa     = mongoose.model("Empresa",     empresaSchema);
const Oportunidade = mongoose.model("Oportunidade", oportunidadeSchema);
const Candidatura = mongoose.model("Candidatura", candidaturaSchema);
const Avaliacao   = mongoose.model("Avaliacao",   avaliacaoSchema);

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

// ====================== MIDDLEWARES ======================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ erro: "Token ausente" });
  try {
    req.user = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

function soEstudante(req, res, next) {
  if (req.user.tipo_usuario !== "estudante")
    return res.status(403).json({ erro: "Apenas estudantes" });
  next();
}

function soEmpresa(req, res, next) {
  if (req.user.tipo_usuario !== "empresa")
    return res.status(403).json({ erro: "Apenas empresas" });
  next();
}

// ====================== HEALTH ======================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    time: new Date().toISOString(),
  });
});

// ====================== AUTH ======================

// Cadastro estudante
app.post("/auth/cadastro-estudante", async (req, res) => {
  try {
    const { nome, email, senha, telefone, faculdade, curso, semestre, cidade, linkedin, portfolio, areas, bio, skills } = req.body;

    if (!nome || !email || !senha)
      return res.status(400).json({ erro: "nome, email e senha são obrigatórios" });

    if (await Usuario.findOne({ email }))
      return res.status(409).json({ erro: "E-mail já cadastrado" });

    const hash = await bcrypt.hash(senha, 10);
    const user = await Usuario.create({ nome, email, senha: hash, tipo_usuario: "estudante" });

    // Cria perfil de estudante junto
    await Estudante.create({
      usuario_id: user._id,
      telefone: telefone || "",
      faculdade: faculdade || "",
      curso: curso || "",
      semestre: semestre || null,
      cidade: cidade || "",
      linkedin: linkedin || "",
      portfolio: portfolio || "",
      areas: areas || "",
      bio: bio || "",
      skills: skills || [],
    });

    res.status(201).json({ token: generateToken(user), usuario: sanitizeUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Cadastro empresa
app.post("/auth/cadastro-empresa", async (req, res) => {
  try {
    const { nome, responsavel, email, senha, telefone, segmento, tamanho } = req.body;

    if (!nome || !email || !senha)
      return res.status(400).json({ erro: "nome, email e senha são obrigatórios" });

    if (await Usuario.findOne({ email }))
      return res.status(409).json({ erro: "E-mail já cadastrado" });

    const hash = await bcrypt.hash(senha, 10);
    const user = await Usuario.create({ nome: responsavel || nome, email, senha: hash, tipo_usuario: "empresa" });

    await Empresa.create({
      usuario_id: user._id,
      nome_empresa: nome,
      responsavel: responsavel || "",
      telefone: telefone || "",
      segmento: segmento || "",
      tamanho: tamanho || "",
    });

    res.status(201).json({ token: generateToken(user), usuario: sanitizeUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ erro: "email e senha obrigatórios" });

    const user = await Usuario.findOne({ email });
    if (!user || !(await bcrypt.compare(senha, user.senha)))
      return res.status(401).json({ erro: "Credenciais inválidas" });

    res.json({ token: generateToken(user), usuario: sanitizeUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro no login" });
  }
});

// Dados do usuário autenticado
app.get("/me", auth, async (req, res) => {
  try {
    const user = await Usuario.findById(req.user.id);
    if (!user) return res.status(404).json({ erro: "Usuário não encontrado" });

    const perfil = req.user.tipo_usuario === "estudante"
      ? await Estudante.findOne({ usuario_id: user._id })
      : await Empresa.findOne({ usuario_id: user._id });

    res.json({ usuario: sanitizeUser(user), perfil: perfil || {} });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== PERFIL ESTUDANTE ======================

// Buscar perfil próprio
app.get("/estudante/perfil", auth, soEstudante, async (req, res) => {
  try {
    const perfil = await Estudante.findOne({ usuario_id: req.user.id });
    if (!perfil) return res.status(404).json({ erro: "Perfil não encontrado" });
    res.json({ perfil });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Atualizar perfil próprio
app.put("/estudante/perfil", auth, soEstudante, async (req, res) => {
  try {
    const campos = ["telefone", "faculdade", "curso", "semestre", "cidade", "linkedin", "portfolio", "areas", "bio", "skills", "disponivel"];
    const update = {};
    campos.forEach(c => { if (req.body[c] !== undefined) update[c] = req.body[c]; });
    update.atualizado_em = new Date();

    // Atualiza nome no usuário se enviado
    if (req.body.nome) await Usuario.findByIdAndUpdate(req.user.id, { nome: req.body.nome });

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

// Perfil público de um estudante (para empresas verem)
app.get("/estudante/:id", auth, async (req, res) => {
  try {
    const user = await Usuario.findById(req.params.id);
    if (!user || user.tipo_usuario !== "estudante")
      return res.status(404).json({ erro: "Estudante não encontrado" });

    const perfil = await Estudante.findOne({ usuario_id: req.params.id });
    const avaliacoes = await Avaliacao.find({ avaliado_id: req.params.id }).sort({ criado_em: -1 }).limit(5);
    const media = avaliacoes.length
      ? (avaliacoes.reduce((s, a) => s + a.nota, 0) / avaliacoes.length).toFixed(1)
      : null;

    res.json({ usuario: sanitizeUser(user), perfil: perfil || {}, avaliacoes, media_nota: media });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== PERFIL EMPRESA ======================

app.get("/empresa/perfil", auth, soEmpresa, async (req, res) => {
  try {
    const perfil = await Empresa.findOne({ usuario_id: req.user.id });
    if (!perfil) return res.status(404).json({ erro: "Perfil não encontrado" });
    res.json({ perfil });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

app.put("/empresa/perfil", auth, soEmpresa, async (req, res) => {
  try {
    const campos = ["nome_empresa", "responsavel", "telefone", "segmento", "tamanho"];
    const update = {};
    campos.forEach(c => { if (req.body[c] !== undefined) update[c] = req.body[c]; });
    update.atualizado_em = new Date();

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

// ====================== BUSCA DE TALENTOS ======================
// GET /talentos?skill=Python&cidade=São Paulo&faculdade=USP&area=Dados&page=1&limit=12
app.get("/talentos", auth, soEmpresa, async (req, res) => {
  try {
    const { skill, cidade, faculdade, area, page = 1, limit = 12 } = req.query;

    const filtro = { disponivel: true };
    if (skill)     filtro.skills    = { $regex: skill, $options: "i" };
    if (cidade)    filtro.cidade    = { $regex: cidade, $options: "i" };
    if (faculdade) filtro.faculdade = { $regex: faculdade, $options: "i" };
    if (area)      filtro.areas     = { $regex: area, $options: "i" };

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Estudante.countDocuments(filtro);
    const perfis = await Estudante.find(filtro).skip(skip).limit(parseInt(limit)).lean();

    // Enriquecer com nome/email do usuário
    const ids = perfis.map(p => p.usuario_id);
    const usuarios = await Usuario.find({ _id: { $in: ids } }).lean();
    const usuarioMap = Object.fromEntries(usuarios.map(u => [String(u._id), u]));

    const resultado = perfis.map(p => ({
      ...p,
      nome: usuarioMap[String(p.usuario_id)]?.nome || "",
      email: usuarioMap[String(p.usuario_id)]?.email || "",
    }));

    res.json({ total, pagina: parseInt(page), limit: parseInt(limit), estudantes: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== OPORTUNIDADES ======================

// Publicar oportunidade
app.post("/oportunidades", auth, soEmpresa, async (req, res) => {
  try {
    const { titulo, descricao, skills, prazo, modalidade, valor } = req.body;
    if (!titulo || !descricao)
      return res.status(400).json({ erro: "titulo e descricao são obrigatórios" });

    const op = await Oportunidade.create({
      empresa_id: req.user.id,
      titulo, descricao,
      skills: skills || [],
      prazo: prazo || "",
      modalidade: modalidade || "Remoto",
      valor: valor || "",
    });
    res.status(201).json({ oportunidade: op });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Listar oportunidades abertas (estudante vê)
// GET /oportunidades?skill=React&modalidade=Remoto&page=1&limit=10
app.get("/oportunidades", auth, async (req, res) => {
  try {
    const { skill, modalidade, page = 1, limit = 10 } = req.query;
    const filtro = { ativa: true };
    if (skill)     filtro.skills     = { $regex: skill, $options: "i" };
    if (modalidade) filtro.modalidade = modalidade;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Oportunidade.countDocuments(filtro);
    const ops = await Oportunidade.find(filtro)
      .sort({ criado_em: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Enriquecer com nome da empresa
    const empIds = ops.map(o => o.empresa_id);
    const empresas = await Empresa.find({ usuario_id: { $in: empIds } }).lean();
    const empMap = Object.fromEntries(empresas.map(e => [String(e.usuario_id), e]));

    const resultado = ops.map(o => ({
      ...o,
      nome_empresa: empMap[String(o.empresa_id)]?.nome_empresa || "",
    }));

    res.json({ total, pagina: parseInt(page), limit: parseInt(limit), oportunidades: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Oportunidades da empresa logada
app.get("/oportunidades/minhas", auth, soEmpresa, async (req, res) => {
  try {
    const ops = await Oportunidade.find({ empresa_id: req.user.id }).sort({ criado_em: -1 });
    res.json({ oportunidades: ops });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Detalhe de uma oportunidade
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

// Editar oportunidade (só dono)
app.put("/oportunidades/:id", auth, soEmpresa, async (req, res) => {
  try {
    const op = await Oportunidade.findOne({ _id: req.params.id, empresa_id: req.user.id });
    if (!op) return res.status(404).json({ erro: "Oportunidade não encontrada ou sem permissão" });

    const campos = ["titulo", "descricao", "skills", "prazo", "modalidade", "valor", "ativa"];
    campos.forEach(c => { if (req.body[c] !== undefined) op[c] = req.body[c]; });
    await op.save();
    res.json({ oportunidade: op });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Encerrar oportunidade
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

// Estudante demonstra interesse em uma oportunidade
app.post("/oportunidades/:id/interesse", auth, soEstudante, async (req, res) => {
  try {
    const op = await Oportunidade.findById(req.params.id);
    if (!op || !op.ativa) return res.status(404).json({ erro: "Oportunidade não disponível" });

    const candidatura = await Candidatura.create({
      oportunidade_id: op._id,
      estudante_id: req.user.id,
    });
    res.status(201).json({ mensagem: "Interesse registrado!", candidatura });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ erro: "Interesse já registrado" });
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Empresa vê candidatos de uma oportunidade
app.get("/oportunidades/:id/candidatos", auth, soEmpresa, async (req, res) => {
  try {
    const op = await Oportunidade.findOne({ _id: req.params.id, empresa_id: req.user.id });
    if (!op) return res.status(404).json({ erro: "Não encontrada ou sem permissão" });

    const candidaturas = await Candidatura.find({ oportunidade_id: op._id }).sort({ criado_em: -1 }).lean();
    const ids = candidaturas.map(c => c.estudante_id);

    const usuarios = await Usuario.find({ _id: { $in: ids } }).lean();
    const perfis   = await Estudante.find({ usuario_id: { $in: ids } }).lean();

    const usuMap  = Object.fromEntries(usuarios.map(u => [String(u._id), u]));
    const perfMap = Object.fromEntries(perfis.map(p => [String(p.usuario_id), p]));

    const resultado = candidaturas.map(c => ({
      candidatura_id: c._id,
      status: c.status,
      criado_em: c.criado_em,
      estudante: {
        id: c.estudante_id,
        nome:      usuMap[String(c.estudante_id)]?.nome || "",
        email:     usuMap[String(c.estudante_id)]?.email || "",
        faculdade: perfMap[String(c.estudante_id)]?.faculdade || "",
        curso:     perfMap[String(c.estudante_id)]?.curso || "",
        cidade:    perfMap[String(c.estudante_id)]?.cidade || "",
        skills:    perfMap[String(c.estudante_id)]?.skills || [],
        linkedin:  perfMap[String(c.estudante_id)]?.linkedin || "",
        portfolio: perfMap[String(c.estudante_id)]?.portfolio || "",
      },
    }));

    res.json({ total: resultado.length, candidatos: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Empresa atualiza status de uma candidatura
// body: { status: "em_andamento" | "concluido" | "recusado" | "visualizado" }
app.put("/candidaturas/:id/status", auth, soEmpresa, async (req, res) => {
  try {
    const { status } = req.body;
    const validos = ["pendente", "visualizado", "em_andamento", "concluido", "recusado"];
    if (!validos.includes(status))
      return res.status(400).json({ erro: `Status inválido. Use: ${validos.join(", ")}` });

    const candidatura = await Candidatura.findById(req.params.id).populate("oportunidade_id");
    if (!candidatura) return res.status(404).json({ erro: "Candidatura não encontrada" });

    // Garante que a oportunidade pertence à empresa
    if (String(candidatura.oportunidade_id.empresa_id) !== String(req.user.id))
      return res.status(403).json({ erro: "Sem permissão" });

    candidatura.status = status;
    candidatura.atualizado_em = new Date();
    await candidatura.save();

    res.json({ candidatura });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Estudante vê suas candidaturas
app.get("/candidaturas/minhas", auth, soEstudante, async (req, res) => {
  try {
    const candidaturas = await Candidatura.find({ estudante_id: req.user.id })
      .sort({ criado_em: -1 })
      .lean();

    const opIds = candidaturas.map(c => c.oportunidade_id);
    const ops   = await Oportunidade.find({ _id: { $in: opIds } }).lean();
    const opMap = Object.fromEntries(ops.map(o => [String(o._id), o]));

    const empIds  = ops.map(o => o.empresa_id);
    const empresas = await Empresa.find({ usuario_id: { $in: empIds } }).lean();
    const empMap  = Object.fromEntries(empresas.map(e => [String(e.usuario_id), e]));

    const resultado = candidaturas.map(c => ({
      candidatura_id: c._id,
      status: c.status,
      criado_em: c.criado_em,
      oportunidade: {
        id:           opMap[String(c.oportunidade_id)]?._id,
        titulo:       opMap[String(c.oportunidade_id)]?.titulo || "",
        skills:       opMap[String(c.oportunidade_id)]?.skills || [],
        modalidade:   opMap[String(c.oportunidade_id)]?.modalidade || "",
        valor:        opMap[String(c.oportunidade_id)]?.valor || "",
        nome_empresa: empMap[String(opMap[String(c.oportunidade_id)]?.empresa_id)]?.nome_empresa || "",
      },
    }));

    res.json({ candidaturas: resultado });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== AVALIAÇÕES ======================

// Criar avaliação (após projeto concluído)
app.post("/avaliacoes", auth, async (req, res) => {
  try {
    const { candidatura_id, nota, comentario } = req.body;
    if (!candidatura_id || !nota)
      return res.status(400).json({ erro: "candidatura_id e nota são obrigatórios" });

    const candidatura = await Candidatura.findById(candidatura_id).populate("oportunidade_id");
    if (!candidatura) return res.status(404).json({ erro: "Candidatura não encontrada" });
    if (candidatura.status !== "concluido")
      return res.status(400).json({ erro: "Só é possível avaliar projetos concluídos" });

    const eh_empresa   = String(candidatura.oportunidade_id.empresa_id) === String(req.user.id);
    const eh_estudante = String(candidatura.estudante_id) === String(req.user.id);
    if (!eh_empresa && !eh_estudante)
      return res.status(403).json({ erro: "Sem permissão para avaliar" });

    const avaliado_id = eh_empresa ? candidatura.estudante_id : candidatura.oportunidade_id.empresa_id;

    const avaliacao = await Avaliacao.create({
      candidatura_id,
      avaliador_id: req.user.id,
      avaliado_id,
      nota,
      comentario: comentario || "",
    });

    res.status(201).json({ avaliacao });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ erro: "Você já avaliou este projeto" });
    res.status(500).json({ erro: "Erro interno" });
  }
});

// Buscar avaliações de um usuário
app.get("/avaliacoes/:usuario_id", auth, async (req, res) => {
  try {
    const avaliacoes = await Avaliacao.find({ avaliado_id: req.params.usuario_id })
      .sort({ criado_em: -1 })
      .lean();

    const media = avaliacoes.length
      ? parseFloat((avaliacoes.reduce((s, a) => s + a.nota, 0) / avaliacoes.length).toFixed(1))
      : null;

    res.json({ total: avaliacoes.length, media_nota: media, avaliacoes });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== STATS (para dashboard) ======================
app.get("/stats", auth, async (req, res) => {
  try {
    if (req.user.tipo_usuario === "empresa") {
      const ops        = await Oportunidade.find({ empresa_id: req.user.id });
      const opIds      = ops.map(o => o._id);
      const candidatos = await Candidatura.countDocuments({ oportunidade_id: { $in: opIds } });
      const ativos     = await Candidatura.countDocuments({ oportunidade_id: { $in: opIds }, status: "em_andamento" });
      const concluidos = await Candidatura.countDocuments({ oportunidade_id: { $in: opIds }, status: "concluido" });

      return res.json({
        vagas_publicadas: ops.length,
        vagas_ativas: ops.filter(o => o.ativa).length,
        total_candidatos: candidatos,
        projetos_ativos: ativos,
        projetos_concluidos: concluidos,
      });
    }

    // Estudante
    const candidaturas = await Candidatura.find({ estudante_id: req.user.id });
    const concluidos   = candidaturas.filter(c => c.status === "concluido").length;
    const avaliacoes   = await Avaliacao.find({ avaliado_id: req.user.id });
    const media        = avaliacoes.length
      ? parseFloat((avaliacoes.reduce((s, a) => s + a.nota, 0) / avaliacoes.length).toFixed(1))
      : null;

    res.json({
      interesses_enviados: candidaturas.length,
      projetos_concluidos: concluidos,
      media_nota: media,
      total_avaliacoes: avaliacoes.length,
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro interno" });
  }
});

// ====================== START ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 RecrutÁgil rodando na porta ${PORT}`));
