/**
 * RecrutÁgil - Backend Production Ready
 * Node.js + Express + MongoDB Atlas + Render
 */

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

app.use(express.json({ limit: "10mb" }));
app.use(cors());

// ====================== ENV VALIDATION ======================

if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI não definida no .env");
  process.exit(1);
}

if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET não definida no .env");
  process.exit(1);
}

// ====================== MONGODB (PRODUCTION SAFE) ======================

const connectMongo = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      maxPoolSize: 10,
    });

    console.log("✅ MongoDB conectado com sucesso");
  } catch (err) {
    console.error("❌ Erro MongoDB:", err.message);

    // 🔥 Render-friendly: retry infinito com delay
    setTimeout(connectMongo, 5000);
  }
};

connectMongo();

// evita crash por desconexão
mongoose.connection.on("disconnected", () => {
  console.log("⚠️ MongoDB desconectado. Reconectando...");
  connectMongo();
});

// ====================== HEALTH CHECK (Render obrigatório) ======================

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    time: new Date().toISOString(),
  });
});

// ====================== MODELS ======================

const usuarioSchema = new mongoose.Schema({
  nome: String,
  email: { type: String, unique: true },
  senha: String,
  tipo_usuario: { type: String, enum: ["estudante", "empresa"] },
  criado_em: { type: Date, default: Date.now },
});

const Usuario = mongoose.model("Usuario", usuarioSchema);

// ====================== AUTH ======================

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ erro: "Token ausente" });

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

// ====================== ROUTES ======================

app.post("/auth/cadastro-estudante", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    const exists = await Usuario.findOne({ email });
    if (exists) return res.status(409).json({ erro: "Email já existe" });

    const hash = await bcrypt.hash(senha, 10);

    const user = await Usuario.create({
      nome,
      email,
      senha: hash,
      tipo_usuario: "estudante",
    });

    const token = jwt.sign(
      { id: user._id, tipo: user.tipo_usuario },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro interno" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    const user = await Usuario.findOne({ email });
    if (!user) return res.status(401).json({ erro: "Inválido" });

    const ok = await bcrypt.compare(senha, user.senha);
    if (!ok) return res.status(401).json({ erro: "Inválido" });

    const token = jwt.sign(
      { id: user._id, tipo: user.tipo_usuario },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ erro: "Erro login" });
  }
});

app.get("/me", auth, async (req, res) => {
  const user = await Usuario.findById(req.user.id);
  res.json(user);
});

// ====================== GLOBAL ERROR HANDLER ======================

app.use((err, req, res, next) => {
  console.error("🔥 ERRO GLOBAL:", err);
  res.status(500).json({ erro: "Erro interno servidor" });
});

// ====================== START ======================

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`🚀 Backend rodando na porta ${PORT}`);
});
