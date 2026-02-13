const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const helmet = require("helmet");
const { body, param, validationResult } = require("express-validator");
const sanitizeHtml = require("sanitize-html");
const rateLimit = require("express-rate-limit");

const app = express();

// CORS restrictivo - configurar según tus dominios de frontend
const corsOptions = {
  origin: function (origin, callback) {
    // Permitir requests sin origin (como Postman, mobile apps)
    if (!origin) return callback(null, true);
    
    // Lista blanca de dominios permitidos - AJUSTAR SEGÚN TU FRONTEND
    const allowedOrigins = [
      'http://localhost:3001',
      'http://localhost:5173',
      'http://127.0.0.1:3001',
      'http://127.0.0.1:5173',
      'https://crud-lqat.vercel.app'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('🚫 CORS bloqueó origen:', origin);
      callback(new Error('No permitido por CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' })); // Limitar tamaño de payload
app.use(helmet());

// ---------------- RATE LIMITING MEJORADO ----------------

// Rate limiter para operaciones de escritura (POST, PUT, DELETE)
const writeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 10, // máximo 10 requests por minuto
  message: {
    error: "Too Many Requests",
    msg: "Demasiadas peticiones, espera 1 minuto"
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // NO aplicar rate limit a localhost en desarrollo
    const ip = req.ip || req.connection.remoteAddress;
    return process.env.NODE_ENV === 'development' && 
           (ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1");
  }
});

// Rate limiter extra estricto para DELETE
const deleteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // máximo 5 deletes cada 15 minutos
  message: {
    error: "Too Many Requests",
    msg: "Demasiadas eliminaciones, espera 15 minutos"
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const ip = req.ip || req.connection.remoteAddress;
    return process.env.NODE_ENV === 'development' && 
           (ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1");
  }
});

const sanitizeInput = (req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === "string") {
        req.body[key] = sanitizeHtml(req.body[key], {
          allowedTags: [],
          allowedAttributes: {}
        });
      }
    }
  }
  next();
};

app.use(sanitizeInput);
// NO aplicar rate limiting globalmente

// ---------------- CONEXIÓN MYSQL ----------------
const db = mysql.createPool({
  host: "mysql-naranja-nestjs.alwaysdata.net",
  user: "naranja-nestjs_fdf",
  password: "naranjajs", // TODO: Mover a variables de entorno en producción
  database: "naranja-nestjs_crud",

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,

  enableKeepAlive: true,
  keepAliveInitialDelay: 0,

  // SSL: solo desactivar verificación en desarrollo
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: true }
    : { rejectUnauthorized: false }
});
setInterval(() => {
  db.query("SELECT 1");
}, 300000); // cada 5 minutos

db.query("SELECT 1", err => {
  if (err) console.error("❌ MySQL not reachable:", err.message);
  else console.log("✅ MySQL pool conectado");
});


// ---------------- VALIDACIONES ----------------
const validarTexto = [
  body("texto")
    .trim()
    .escape()
    .isLength({ min: 1, max: 50 })
    .withMessage("Texto inválido"),
];

const validarId = [
  param("id").isInt({ min: 1 }).withMessage("ID inválido"),
];

// ---------------- MIDDLEWARE SEGURIDAD ----------------
const bloquearLocalhost = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  
  // Bloquear todas las variantes de localhost
  if (ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1") {
    console.log("🚫 Petición bloqueada desde localhost, IP:", ip, "Ruta:", req.method, req.path);
    return res.status(403).json({ 
      error: "Forbidden", 
      msg: "Operaciones destructivas no permitidas desde localhost" 
    });
  }
  
  next();
};

// ---------------- CRUD ----------------

// CREATE - CON rate limiting
app.post("/crud", writeLimiter, validarTexto, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { texto } = req.body;

  const sql = "INSERT INTO crud (texto) VALUES (?)";
  db.query(sql, [texto], (err, result) => {
    if (err) {
      console.error('DB Error en INSERT:', err.message);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
    res.json({ msg: "Insertado", id: result.insertId });
  });
});

// READ ALL - SIN rate limiting
app.get("/crud", (req, res) => {
  db.query("SELECT * FROM crud", (err, rows) => {
    if (err) {
      console.error('DB Error en SELECT:', err.message);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
    res.json(rows);
  });
});

// UPDATE - CON rate limiting y bloqueo localhost
app.put("/crud/:id", bloquearLocalhost, writeLimiter, [...validarId, ...validarTexto], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { texto } = req.body;

  const sql = "UPDATE crud SET texto=? WHERE id=?";
  db.query(sql, [texto, req.params.id], (err, result) => {
    if (err) {
      console.error('DB Error en UPDATE:', err.message);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ msg: "No existe" });
    }
    res.json({ msg: "Actualizado" });
  });
});

// DELETE - CON rate limiting extra estricto, bloqueo localhost y auditoría
app.delete("/crud/:id", bloquearLocalhost, deleteLimiter, validarId, (req, res) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const ip = req.ip || req.connection.remoteAddress;
  const id = req.params.id;
  
  console.log(`🧨 DELETE - IP: ${ip} | ID: ${id} | Time: ${new Date().toISOString()}`);
  
  const sql = "DELETE FROM crud WHERE id=?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error(`❌ DELETE FAILED - IP: ${ip} | ID: ${id} | Error: ${err.message}`);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
    if (result.affectedRows === 0) {
      console.log(`⚠️  DELETE - Registro no encontrado | IP: ${ip} | ID: ${id}`);
      return res.status(404).json({ msg: "No existe" });
    }
    console.log(`✅ DELETE SUCCESS - IP: ${ip} | ID: ${id}`);
    res.json({ msg: "Eliminado" });
  });
});

// ---------------- SERVIDOR ----------------
const PORT = 3000;
const server = app.listen(PORT, () => {
  console.info(`🚀 Servidor ejecutándose en puerto ${PORT}`);
  console.info(`📊 Modo: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('\n🛑 Señal de apagado recibida, cerrando servidor...');
  
  server.close(() => {
    console.log('✅ Servidor HTTP cerrado');
    
    db.end((err) => {
      if (err) {
        console.error('❌ Error cerrando pool MySQL:', err.message);
        process.exit(1);
      }
      console.log('✅ Pool MySQL cerrado');
      process.exit(0);
    });
  });
  
  // Forzar cierre después de 10 segundos
  setTimeout(() => {
    console.error('⏱️  Timeout - Forzando cierre');
    process.exit(1);
  }, 10000);
}
