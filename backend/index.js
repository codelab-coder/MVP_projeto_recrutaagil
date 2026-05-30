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
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI não definida");
  process.exit(1);
}

if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET não definida");
  process.exit(1);
}

// ====================== MONGO CONNECTION (ROBUSTO) ======================
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      maxPoolSize: 10,
    });

    console.log("✅ MongoDB conectado");
  } catch (err) {
    console.log("❌ erro MongoDB:", err.message);
    setTimeout(connectDB, 5000);
  }
}

connectDB();

mongoose.connection.on("disconnected", () => {
  console.log("⚠️ MongoDB caiu, reconectando...");
  connectDB();
});

// ====================== MODELO ======================
const usuarioSchema = new mongoose.Schema({
  nome: String,
  email: { type: String, unique: true },
  senha: String,
  tipo_usuario: { type: String, enum: ["estudante", "empresa"] },
  criado_em: { type: Date, default: Date.now },
});

const Usuario = mongoose.model("Usuario", usuarioSchema);

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
    {
      id: user._id,
      tipo_usuario: user.tipo_usuario,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ====================== AUTH MIDDLEWARE ======================
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ erro: "Token ausente" });
  }

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

// ====================== HEALTH ======================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    time: new Date().toISOString(),
  });
});

// ====================== CADASTRO ======================
app.post("/auth/cadastro-estudante", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    const exists = await Usuario.findOne({ email });
    if (exists) {
      return res.status(409).json({ erro: "Email já existe" });
    }

    const hash = await bcrypt.hash(senha, 10);

    const user = await Usuario.create({
      nome,
      email,
      senha: hash,
      tipo_usuario: "estudante",
    });

    const token = generateToken(user);

    res.status(201).json({
      token,
      usuario: sanitizeUser(user),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro interno servidor" });
  }
});

app.post("/auth/cadastro-empresa", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    const exists = await Usuario.findOne({ email });
    if (exists) {
      return res.status(409).json({ erro: "Email já existe" });
    }

    const hash = await bcrypt.hash(senha, 10);

    const user = await Usuario.create({
      nome,
      email,
      senha: hash,
      tipo_usuario: "empresa",
    });

    const token = generateToken(user);

    res.status(201).json({
      token,
      usuario: sanitizeUser(user),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro interno servidor" });
  }
});

// ====================== LOGIN ======================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    const user = await Usuario.findOne({ email });

    if (!user) {
      return res.status(401).json({ erro: "Credenciais inválidas" });
    }

    const ok = await bcrypt.compare(senha, user.senha);

    if (!ok) {
      return res.status(401).json({ erro: "Credenciais inválidas" });
    }

    const token = generateToken(user);

    res.json({
      token,
      usuario: sanitizeUser(user),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro login" });
  }
});

// ====================== ME ======================
app.get("/me", auth, async (req, res) => {
  const user = await Usuario.findById(req.user.id);

  if (!user) {
    return res.status(404).json({ erro: "Usuário não encontrado" });
  }

  res.json({
    usuario: sanitizeUser(user),
  });
});

// ====================== START ======================
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`🚀 RecrutÁgil rodando na porta ${PORT}`);
});
