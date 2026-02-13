const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const helmet = require("helmet");
const { body, param, validationResult } = require("express-validator");
const sanitizeHtml = require("sanitize-html");
const rateLimit = require("express-rate-limit");

const app = express();

// CRÍTICO: Configurar Express para confiar en proxies (Render + Cloudflare)
// Esto hace que req.ip lea correctamente X-Forwarded-For
app.set('trust proxy', true);

// CORS restrictivo - configurar según tus dominios de frontend
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3001',
      'http://localhost:5173',
      'http://127.0.0.1:3001',
      'http://127.0.0.1:5173',
      'https://crud-lqat.vercel.app'
    ];
    
    // Si el origen está en la lista blanca, permitir
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } 
    // Si NO hay origen (navegador directo o Postman), BLOQUEAR
    else if (!origin) {
      console.log('🚫 Acceso directo bloqueado (Sin Origin)');
      callback(new Error('Acceso directo no permitido. Se requiere un Origin válido.'));
    } 
    // Cualquier otro origen no autorizado
    else {
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

// Función helper para obtener la IP real del cliente
const getRealIP = (req) => {
  // Prioridad de headers (Cloudflare > X-Forwarded-For > req.ip)
  return req.headers['cf-connecting-ip'] 
         || req.headers['true-client-ip']
         || (req.headers['x-forwarded-for']?.split(',')[0]?.trim())
         || req.ip 
         || req.connection.remoteAddress;
};

// OPCIÓN 1: IP Whitelist (COMENTAR si no quieres usarlo)
// Solo permite IPs específicas para operaciones destructivas
const ipWhitelist = (req, res, next) => {
  const ip = getRealIP(req);
  
  // Lista de IPs permitidas - AJUSTAR SEGÚN TUS NECESIDADES
  const allowedIPs = [
    // Agrega aquí las IPs que DEBEN poder hacer DELETE/UPDATE
    // Ejemplos:
    // '192.168.1.100',
    // '203.0.113.45',
    // '::ffff:192.168.1.100'
  ];
  
  // Si la lista está vacía, permitir todo (para no bloquear accidentalmente)
  if (allowedIPs.length === 0) {
    return next();
  }
  
  if (!allowedIPs.includes(ip)) {
    console.log("🚫 IP NO AUTORIZADA BLOQUEADA");
    console.log("   IP rechazada:", ip);
    console.log("   Ruta:", req.method, req.path);
    console.log("   User-Agent:", req.headers['user-agent']);
    console.log("   Timestamp:", new Date().toISOString());
    
    return res.status(403).json({
      error: "Forbidden",
      msg: "Tu IP no está autorizada para esta operación"
    });
  }
  
  next();
};

// Middleware anti-bot: detectar y bloquear bots maliciosos
const antiBot = (req, res, next) => {
  const userAgent = req.headers['user-agent'] || '';
  const ip = getRealIP(req);
  
  // EXCEPCIÓN: Permitir requests internos autorizados en Render
  const isInternalRender = req.ip === "::1" || req.ip === "127.0.0.1" || req.ip === "::ffff:127.0.0.1";
  const renderInternalToken = req.headers['x-internal-token']; // Token secreto para servicios internos
  
  if (isInternalRender && renderInternalToken === process.env.INTERNAL_TOKEN) {
    // Request interno autorizado en Render
    return next();
  }
  
  // Lista negra de patrones de bots conocidos
  const botPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python-requests/i,  // ← BLOQUEAR Python requests específicamente
    /python/i,
    /java/i,
    /go-http/i,
    /axios/i,
    /node-fetch/i,
    /^$/  // User-Agent vacío
  ];
  
  // Verificar si coincide con patrones de bot
  const isBot = botPatterns.some(pattern => pattern.test(userAgent));
  
  if (isBot) {
    console.log("🤖 BOT DETECTADO Y BLOQUEADO");
    console.log("   IP Real:", ip);
    console.log("   User-Agent:", userAgent);
    console.log("   Ruta:", req.method, req.path);
    console.log("   Timestamp:", new Date().toISOString());
    console.log("   Headers:", JSON.stringify(req.headers, null, 2));
    
    return res.status(403).json({
      error: "Forbidden",
      msg: "Acceso denegado para bots automatizados"
    });
  }
  
  next();
};

const bloquearLocalhost = (req, res, next) => {
  const ip = getRealIP(req); // ← USAR IP REAL
  
  // EN RENDER/PRODUCCIÓN: No bloquear localhost (tráfico interno legítimo)
  // Solo bloquear en desarrollo local
  if (process.env.RENDER || process.env.NODE_ENV === 'production') {
    return next(); // Permitir todo en producción
  }
  
  // Bloquear todas las variantes de localhost SOLO EN DESARROLLO
  if (ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1") {
    // LOG FORENSE COMPLETO
    console.log("=".repeat(80));
    console.log("🚫 PETICIÓN BLOQUEADA DESDE LOCALHOST");
    console.log("⏰ Timestamp:", new Date().toISOString());
    console.log("🔗 Ruta:", req.method, req.path);
    console.log("🌐 IP detectada:", ip);
    console.log("🌐 IP REAL (Cloudflare):", getRealIP(req));
    console.log("📡 req.ip:", req.ip);
    console.log("🔌 req.connection.remoteAddress:", req.connection.remoteAddress);
    console.log("🔍 X-Forwarded-For:", req.headers['x-forwarded-for']);
    console.log("🔍 X-Real-IP:", req.headers['x-real-ip']);
    console.log("🔍 CF-Connecting-IP:", req.headers['cf-connecting-ip']); // Cloudflare
    console.log("🤖 User-Agent:", req.headers['user-agent']);
    console.log("🌍 Origin:", req.headers['origin']);
    console.log("🔗 Referer:", req.headers['referer']);
    console.log("📋 Todos los headers:", JSON.stringify(req.headers, null, 2));
    console.log("=".repeat(80));
    
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

// UPDATE - CON anti-bot, rate limiting y bloqueo localhost
app.put("/crud/:id", antiBot, bloquearLocalhost, writeLimiter, [...validarId, ...validarTexto], (req, res) => {
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

// DELETE - CON anti-bot, rate limiting extra estricto, bloqueo localhost y auditoría
app.delete("/crud/:id", antiBot, bloquearLocalhost, deleteLimiter, validarId, (req, res) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const ip = getRealIP(req); // ← USAR IP REAL
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
