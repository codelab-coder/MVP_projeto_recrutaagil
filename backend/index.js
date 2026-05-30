/**
 * RecrutÁgil - Backend MongoDB
 * Node.js + Express + MongoDB + JWT
 */

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());

// ====================== CONEXÃO ======================

const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb://localhost:27017/recrutaagil";

mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
  })
  .then(() => console.log("✅ MongoDB conectado"))
  .catch((err) => {
    console.error("❌ MongoDB erro:", err);
    process.exit(1);
  });

// ====================== SCHEMAS ======================

const usuarioSchema = new mongoose.Schema({
  nome: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },

  senha: {
    type: String,
    required: true
  },

  tipo_usuario: {
    type: String,
    enum: ["estudante", "empresa"],
    required: true
  },

  telefone: String,

  cidade: String,

  criado_em: {
    type: Date,
    default: Date.now
  }
});

// ====================== ESTUDANTE ======================

const estudanteSchema =
  new mongoose.Schema({

    usuario: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Usuario",
      required: true
    },

    faculdade: String,

    curso: String,

    semestre: Number,

    linkedin: String,

    portfolio: String,

    skills: [String],

    areas_interesse: [String],

    bio: String,

    foto_perfil: String,

    curriculo_pdf: String,

    disponivel_para_projetos: {
      type: Boolean,
      default: true
    },

    nivel: {
      type: String,
      enum: [
        "iniciante",
        "intermediario",
        "avancado"
      ],
      default: "iniciante"
    },

    projetos_realizados: {
      type: Number,
      default: 0
    },

    avaliacao_media: {
      type: Number,
      default: 0
    },

    total_avaliacoes: {
      type: Number,
      default: 0
    }

  });

// índice para busca rápida

estudanteSchema.index({
  skills: 1
});

estudanteSchema.index({
  curso: 1
});

estudanteSchema.index({
  faculdade: 1
});

// ====================== EMPRESA ======================

const empresaSchema =
  new mongoose.Schema({

    usuario: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Usuario",
      required: true
    },

    nome_empresa: String,

    responsavel: String,

    email_corporativo: String,

    segmento: String,

    tamanho: String,

    descricao: String

  });

// ====================== OPORTUNIDADE ======================

const oportunidadeSchema =
  new mongoose.Schema({

    empresa: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Empresa",
      required: true
    },

    titulo: {
      type: String,
      required: true
    },

    descricao: {
      type: String,
      required: true
    },

    skills: [String],

    prazo: Date,

    modalidade: String,

    valor: Number,

    status: {
      type: String,
      enum: [
        "ativa",
        "fechada",
        "concluida"
      ],
      default: "ativa"
    },

    criado_em: {
      type: Date,
      default: Date.now
    }

  });

// ====================== CANDIDATURA ======================

const candidaturaSchema =
  new mongoose.Schema({

    oportunidade: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Oportunidade",
      required: true
    },

    estudante: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Estudante",
      required: true
    },

    status: {
      type: String,
      enum: [
        "pendente",
        "visualizado",
        "aceito",
        "recusado",
        "concluido"
      ],
      default: "pendente"
    }

  }, {
    timestamps: true
  });

// ====================== CONVITES ======================

const conviteSchema =
  new mongoose.Schema({

    empresa: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Empresa",
      required: true
    },

    estudante: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Estudante",
      required: true
    },

    mensagem: {
      type: String,
      default: ""
    },

    status: {
      type: String,
      enum: [
        "pendente",
        "aceito",
        "recusado"
      ],
      default: "pendente"
    },

    criado_em: {
      type: Date,
      default: Date.now
    }

  });

// ====================== AVALIAÇÃO ======================

const avaliacaoSchema =
  new mongoose.Schema({

    estudante: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Estudante",
      required: true
    },

    empresa: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Empresa",
      required: true
    },

    oportunidade: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Oportunidade"
    },

    nota: {
      type: Number,
      min: 1,
      max: 5,
      required: true
    },

    comentario: String,

    criado_em: {
      type: Date,
      default: Date.now
    }

  });

// ====================== NOTIFICAÇÃO ======================

const notificacaoSchema =
  new mongoose.Schema({

    usuario: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Usuario",
      required: true
    },

    mensagem: {
      type: String,
      required: true
    },

    lida: {
      type: Boolean,
      default: false
    },

    criado_em: {
      type: Date,
      default: Date.now
    }

  });

// ====================== MODELS ======================

const Usuario =
  mongoose.model(
    "Usuario",
    usuarioSchema
  );

const Estudante =
  mongoose.model(
    "Estudante",
    estudanteSchema
  );

const Empresa =
  mongoose.model(
    "Empresa",
    empresaSchema
  );

const Oportunidade =
  mongoose.model(
    "Oportunidade",
    oportunidadeSchema
  );

const Candidatura =
  mongoose.model(
    "Candidatura",
    candidaturaSchema
  );

const Convite =
  mongoose.model(
    "Convite",
    conviteSchema
  );

const Avaliacao =
  mongoose.model(
    "Avaliacao",
    avaliacaoSchema
  );

const Notificacao =
  mongoose.model(
    "Notificacao",
    notificacaoSchema
  );
// ====================== MIDDLEWARES ======================

function authMiddleware(req, res, next) {

  const authHeader =
    req.headers.authorization;

  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ")
  ) {

    return res.status(401).json({
      erro: "Token não fornecido."
    });

  }

  const token =
    authHeader.split(" ")[1];

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET ||
      "recrutaagil_secret"
    );

    req.user = decoded;

    next();

  } catch {

    return res.status(401).json({
      erro: "Token inválido ou expirado."
    });

  }

}

function apenasEmpresa(
  req,
  res,
  next
) {

  if (
    req.user.tipo_usuario !==
    "empresa"
  ) {

    return res.status(403).json({
      erro:
        "Acesso restrito a empresas."
    });

  }

  next();

}

function apenasEstudante(
  req,
  res,
  next
) {

  if (
    req.user.tipo_usuario !==
    "estudante"
  ) {

    return res.status(403).json({
      erro:
        "Acesso restrito a estudantes."
    });

  }

  next();

}

// ====================== HEALTH ======================

app.get("/", (req, res) => {

  res.json({

    status: "ok",

    app: "RecrutÁgil API",

    versao: "2.0.0"

  });

});

// ====================== CADASTRO ESTUDANTE ======================

app.post(
  "/auth/cadastro-estudante",
  async (req, res) => {

    try {

      const {

        nome,
        email,
        senha,
        telefone,
        cidade,

        faculdade,
        curso,
        semestre,

        linkedin,
        portfolio,

        skills,
        areas_interesse,

        bio,

        foto_perfil,
        curriculo_pdf,

        disponivel_para_projetos,
        nivel

      } = req.body;

      const existe =
        await Usuario.findOne({
          email
        });

      if (existe) {

        return res
          .status(409)
          .json({
            erro:
              "E-mail já cadastrado."
          });

      }

      const hash =
        await bcrypt.hash(
          senha,
          10
        );

      const usuario =
        await Usuario.create({

          nome,

          email,

          senha: hash,

          telefone,

          cidade,

          tipo_usuario:
            "estudante"

        });

      await Estudante.create({

        usuario:
          usuario._id,

        faculdade,

        curso,

        semestre,

        linkedin,

        portfolio,

        skills:
          skills || [],

        areas_interesse:
          areas_interesse || [],

        bio,

        foto_perfil,

        curriculo_pdf,

        disponivel_para_projetos,

        nivel

      });

      const token =
        jwt.sign(

          {

            id: usuario._id,

            email:
              usuario.email,

            tipo_usuario:
              "estudante"

          },

          process.env
            .JWT_SECRET ||
            "recrutaagil_secret",

          {
            expiresIn: "7d"
          }

        );

      res.status(201).json({

        mensagem:
          "Estudante cadastrado com sucesso.",

        token,

        usuario: {

          id:
            usuario._id,

          nome:
            usuario.nome,

          email:
            usuario.email,

          tipo_usuario:
            "estudante"

        }

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro interno do servidor."
      });

    }

  }
);

// ====================== CADASTRO EMPRESA ======================

app.post(
  "/auth/cadastro-empresa",
  async (req, res) => {

    try {

      const {

        nome,
        email,
        senha,

        telefone,
        cidade,

        nome_empresa,
        responsavel,

        email_corporativo,

        segmento,
        tamanho,

        descricao

      } = req.body;

      const existe =
        await Usuario.findOne({
          email
        });

      if (existe) {

        return res
          .status(409)
          .json({
            erro:
              "E-mail já cadastrado."
          });

      }

      const hash =
        await bcrypt.hash(
          senha,
          10
        );

      const usuario =
        await Usuario.create({

          nome,

          email,

          senha: hash,

          telefone,

          cidade,

          tipo_usuario:
            "empresa"

        });

      await Empresa.create({

        usuario:
          usuario._id,

        nome_empresa,

        responsavel,

        email_corporativo,

        segmento,

        tamanho,

        descricao

      });

      const token =
        jwt.sign(

          {

            id: usuario._id,

            email:
              usuario.email,

            tipo_usuario:
              "empresa"

          },

          process.env
            .JWT_SECRET ||
            "recrutaagil_secret",

          {
            expiresIn: "7d"
          }

        );

      res.status(201).json({

        mensagem:
          "Empresa cadastrada com sucesso.",

        token,

        usuario: {

          id:
            usuario._id,

          nome:
            usuario.nome,

          email:
            usuario.email,

          tipo_usuario:
            "empresa"

        }

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro interno do servidor."
      });

    }

  }
);

// ====================== LOGIN ======================

app.post(
  "/auth/login",
  async (req, res) => {

    try {

      const {
        email,
        senha
      } = req.body;

      const usuario =
        await Usuario.findOne({
          email
        });

      if (
        !usuario
      ) {

        return res
          .status(401)
          .json({
            erro:
              "Credenciais inválidas."
          });

      }

      const senhaCorreta =
        await bcrypt.compare(
          senha,
          usuario.senha
        );

      if (
        !senhaCorreta
      ) {

        return res
          .status(401)
          .json({
            erro:
              "Credenciais inválidas."
          });

      }

      const token =
        jwt.sign(

          {

            id:
              usuario._id,

            email:
              usuario.email,

            tipo_usuario:
              usuario.tipo_usuario

          },

          process.env
            .JWT_SECRET ||
            "recrutaagil_secret",

          {
            expiresIn:
              "7d"
          }

        );

      res.json({

        token,

        usuario: {

          id:
            usuario._id,

          nome:
            usuario.nome,

          email:
            usuario.email,

          tipo_usuario:
            usuario.tipo_usuario

        }

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro interno do servidor."
      });

    }

  }
);

// ====================== PERFIL LOGADO ======================

app.get(
  "/me",
  authMiddleware,
  async (req, res) => {

    try {

      const usuario =
        await Usuario.findById(
          req.user.id
        );

      if (
        !usuario
      ) {

        return res
          .status(404)
          .json({
            erro:
              "Usuário não encontrado."
          });

      }

      if (
        usuario.tipo_usuario ===
        "estudante"
      ) {

        const estudante =
          await Estudante
            .findOne({

              usuario:
                usuario._id

            });

        return res.json({

          usuario,

          estudante

        });

      }

      const empresa =
        await Empresa.findOne({

          usuario:
            usuario._id

        });

      res.json({

        usuario,

        empresa

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro interno do servidor."
      });

    }

  }
);
// ====================== TALENTOS ======================

// Buscar talentos
app.get(
  "/talentos",
  authMiddleware,
  async (req, res) => {

    try {

      const {
        skill,
        curso,
        faculdade,
        nivel,
        cidade,
        pagina = 1,
        limite = 20
      } = req.query;

      const filtro = {
        disponivel_para_projetos: true
      };

      if (skill) {
        filtro.skills = {
          $regex: skill,
          $options: "i"
        };
      }

      if (curso) {
        filtro.curso = {
          $regex: curso,
          $options: "i"
        };
      }

      if (faculdade) {
        filtro.faculdade = {
          $regex: faculdade,
          $options: "i"
        };
      }

      if (nivel) {
        filtro.nivel = nivel;
      }

      let estudantes =
        await Estudante.find(filtro)
          .populate(
            "usuario",
            "nome email cidade"
          )
          .sort({
            avaliacao_media: -1,
            projetos_realizados: -1
          })
          .skip(
            (pagina - 1) * limite
          )
          .limit(
            Number(limite)
          );

      // filtro cidade (vem do usuário)
      if (cidade) {

        estudantes =
          estudantes.filter(
            (item) =>
              item.usuario?.cidade
                ?.toLowerCase()
                .includes(
                  cidade.toLowerCase()
                )
          );

      }

      const total =
        await Estudante.countDocuments(
          filtro
        );

      res.json({

        total,

        pagina:
          Number(pagina),

        resultados:
          estudantes

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao buscar talentos."
      });

    }

  }
);

// Perfil público do talento
app.get(
  "/talentos/:id",
  async (req, res) => {

    try {

      const estudante =
        await Estudante
          .findById(
            req.params.id
          )
          .populate(
            "usuario",
            "nome email cidade"
          );

      if (!estudante) {

        return res
          .status(404)
          .json({
            erro:
              "Talento não encontrado."
          });

      }

      res.json(estudante);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao carregar talento."
      });

    }

  }
);

// ====================== CONVITES ======================

// Empresa envia convite
app.post(
  "/convites",
  authMiddleware,
  apenasEmpresa,
  async (req, res) => {

    try {

      const {
        estudante,
        mensagem
      } = req.body;

      const empresa =
        await Empresa.findOne({
          usuario:
            req.user.id
        });

      if (!empresa) {

        return res
          .status(404)
          .json({
            erro:
              "Empresa não encontrada."
          });

      }

      const estudanteExiste =
        await Estudante.findById(
          estudante
        );

      if (!estudanteExiste) {

        return res
          .status(404)
          .json({
            erro:
              "Estudante não encontrado."
          });

      }

      const convite =
        await Convite.create({

          empresa:
            empresa._id,

          estudante,

          mensagem

        });

      const usuarioAluno =
        await Usuario.findById(
          estudanteExiste.usuario
        );

      await Notificacao.create({

        usuario:
          usuarioAluno._id,

        mensagem:
          "Você recebeu um novo convite."

      });

      res.status(201).json({

        mensagem:
          "Convite enviado com sucesso.",

        convite

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao enviar convite."
      });

    }

  }
);

// Convites do estudante
app.get(
  "/meus-convites",
  authMiddleware,
  apenasEstudante,
  async (req, res) => {

    try {

      const estudante =
        await Estudante.findOne({

          usuario:
            req.user.id

        });

      const convites =
        await Convite.find({

          estudante:
            estudante._id

        })
          .populate(
            "empresa"
          )
          .sort({
            criado_em: -1
          });

      res.json(convites);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao listar convites."
      });

    }

  }
);

// Aceitar convite
app.patch(
  "/convites/:id/aceitar",
  authMiddleware,
  apenasEstudante,
  async (req, res) => {

    try {

      const convite =
        await Convite.findById(
          req.params.id
        );

      if (!convite) {

        return res
          .status(404)
          .json({
            erro:
              "Convite não encontrado."
          });

      }

      convite.status =
        "aceito";

      await convite.save();

      res.json({

        mensagem:
          "Convite aceito.",

        convite

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao aceitar convite."
      });

    }

  }
);

// Recusar convite
app.patch(
  "/convites/:id/recusar",
  authMiddleware,
  apenasEstudante,
  async (req, res) => {

    try {

      const convite =
        await Convite.findById(
          req.params.id
        );

      if (!convite) {

        return res
          .status(404)
          .json({
            erro:
              "Convite não encontrado."
          });

      }

      convite.status =
        "recusado";

      await convite.save();

      res.json({

        mensagem:
          "Convite recusado.",

        convite

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao recusar convite."
      });

    }

  }
);

// Convites enviados pela empresa
app.get(
  "/convites-enviados",
  authMiddleware,
  apenasEmpresa,
  async (req, res) => {

    try {

      const empresa =
        await Empresa.findOne({

          usuario:
            req.user.id

        });

      const convites =
        await Convite.find({

          empresa:
            empresa._id

        })
          .populate({
            path: "estudante",
            populate: {
              path: "usuario",
              model:
                "Usuario"
            }
          })
          .sort({
            criado_em: -1
          });

      res.json(convites);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao listar convites."
      });

    }

  }
);
// ====================== OPORTUNIDADES ======================

// Listar oportunidades
app.get(
  "/oportunidades",
  async (req, res) => {

    try {

      const {
        skill,
        modalidade
      } = req.query;

      let query = {
        status: "ativa"
      };

      if (skill) {

        query.skills = {
          $regex: skill,
          $options: "i"
        };

      }

      if (modalidade) {

        query.modalidade =
        new RegExp(
          modalidade,
          "i"
        );

      }

      const oportunidades =
        await Oportunidade.find(
          query
        )
          .populate(
            "empresa"
          )
          .sort({
            criado_em: -1
          });

      res.json(
        oportunidades
      );

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao listar oportunidades."
      });

    }

  }
);

// Criar oportunidade
app.post(
  "/oportunidades",
  authMiddleware,
  apenasEmpresa,
  async (req, res) => {

    try {

      const empresa =
        await Empresa.findOne({

          usuario:
            req.user.id

        });

      if (!empresa) {

        return res
          .status(404)
          .json({
            erro:
              "Empresa não encontrada."
          });

      }

      const oportunidade =
        await Oportunidade.create({

          empresa:
            empresa._id,

          titulo:
            req.body.titulo,

          descricao:
            req.body.descricao,

          skills:
            req.body.skills || [],

          modalidade:
            req.body.modalidade,

          valor:
            req.body.valor,

          prazo:
            req.body.prazo

        });

      res.status(201).json(
        oportunidade
      );

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao criar oportunidade."
      });

    }

  }
);

// Candidatar-se
app.post(
  "/oportunidades/:id/candidatar",
  authMiddleware,
  apenasEstudante,
  async (req, res) => {

    try {

      const estudante =
        await Estudante.findOne({

          usuario:
            req.user.id

        });

      const candidaturaExistente =
        await Candidatura.findOne({

          oportunidade:
            req.params.id,

          estudante:
            estudante._id

        });

      if (
        candidaturaExistente
      ) {

        return res
          .status(409)
          .json({
            erro:
              "Você já se candidatou."
          });

      }

      const candidatura =
        await Candidatura.create({

          oportunidade:
            req.params.id,

          estudante:
            estudante._id

        });

      res.status(201).json({
        mensagem:
          "Candidatura realizada com sucesso.",
        candidatura
      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao realizar candidatura."
      });

    }

  }
);

// ====================== AVALIAÇÕES ======================

// Criar avaliação
app.post(
  "/avaliacoes",
  authMiddleware,
  apenasEmpresa,
  async (req, res) => {

    try {

      const empresa =
        await Empresa.findOne({

          usuario:
            req.user.id

        });

      const avaliacao =
        await Avaliacao.create({

          empresa:
            empresa._id,

          estudante:
            req.body.estudante,

          oportunidade:
            req.body.oportunidade,

          nota:
            req.body.nota,

          comentario:
            req.body.comentario

        });

      const avaliacoes =
        await Avaliacao.find({

          estudante:
            req.body.estudante

        });

      const media =
        avaliacoes.reduce(
          (acc, item) =>
            acc + item.nota,
          0
        ) /
        avaliacoes.length;

      await Estudante.findByIdAndUpdate(

        req.body.estudante,

        {

          avaliacao_media:
            Number(
              media.toFixed(1)
            ),

          total_avaliacoes:
            avaliacoes.length

        }

      );

      res.status(201).json(
        avaliacao
      );

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao criar avaliação."
      });

    }

  }
);

// ====================== NOTIFICAÇÕES ======================

// Listar notificações
app.get(
  "/notificacoes",
  authMiddleware,
  async (req, res) => {

    try {

      const notificacoes =
        await Notificacao.find({

          usuario:
            req.user.id

        })
          .sort({
            criado_em: -1
          });

      res.json(
        notificacoes
      );

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao carregar notificações."
      });

    }

  }
);

// Marcar notificação como lida
app.patch(
  "/notificacoes/:id",
  authMiddleware,
  async (req, res) => {

    try {

      const notificacao =
        await Notificacao.findByIdAndUpdate(

          req.params.id,

          {
            lida: true
          },

          {
            new: true
          }

        );

      res.json(
        notificacao
      );

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao atualizar notificação."
      });

    }

  }
);

// ====================== DASHBOARD ======================

// Dashboard estudante
app.get(
  "/dashboard-estudante",
  authMiddleware,
  apenasEstudante,
  async (req, res) => {

    try {

      const estudante =
        await Estudante.findOne({

          usuario:
            req.user.id

        });

      const candidaturas =
        await Candidatura.countDocuments({

          estudante:
            estudante._id

        });

      const convites =
        await Convite.countDocuments({

          estudante:
            estudante._id

        });

      res.json({

        candidaturas,

        convites,

        avaliacao_media:
          estudante.avaliacao_media,

        projetos_realizados:
          estudante.projetos_realizados

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao carregar dashboard."
      });

    }

  }
);

// Dashboard empresa
app.get(
  "/dashboard-empresa",
  authMiddleware,
  apenasEmpresa,
  async (req, res) => {

    try {

      const empresa =
        await Empresa.findOne({

          usuario:
            req.user.id

        });

      const oportunidades =
        await Oportunidade.countDocuments({

          empresa:
            empresa._id

        });

      const convites =
        await Convite.countDocuments({

          empresa:
            empresa._id

        });

      res.json({

        oportunidades,

        convites

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        erro:
          "Erro ao carregar dashboard."
      });

    }

  }
);

// ====================== START ======================

const PORT =
  process.env.PORT ||
  3001;

app.listen(
  PORT,
  () => {

    console.log(
      `🚀 RecrutÁgil rodando na porta ${PORT}`
    );

  }
);
