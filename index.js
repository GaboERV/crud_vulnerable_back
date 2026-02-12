const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const helmet = require("helmet");
const { body, param, validationResult } = require("express-validator");
const sanitizeHtml = require("sanitize-html");

const app = express();

// ---------------- MIDDLEWARE ORDER MATTERS ----------------
app.use(helmet({
  contentSecurityPolicy: false, // Adjust based on your needs
}));
app.use(cors());
app.use(express.json());

// ---------------- RATE LIMITING ----------------
const requestTimes = new Map();
const COOLDOWN_MS = 5000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, time] of requestTimes.entries()) {
    if (now - time > COOLDOWN_MS) requestTimes.delete(ip);
  }
}, 60000);

const rateLimitMiddleware = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();

  if (requestTimes.has(ip)) {
    if (now - requestTimes.get(ip) < COOLDOWN_MS) {
      return res.status(429).json({
        error: "Too Many Requests",
        msg: "Espera 5 segundos antes de volver a intentar",
      });
    }
  }

  requestTimes.set(ip, now);
  next();
};

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
app.use(rateLimitMiddleware);

// ---------------- CONEXIÓN MYSQL ----------------
const db = mysql.createConnection({
  host: "mysql-naranja-nestjs.alwaysdata.net",
  user: "naranja-nestjs_fdf",
  password: "naranjajs",
  database: "naranja-nestjs_crud",
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.error('❌ Error connecting to MySQL:', err.message);
    process.exit(1);
  }
  console.log('✅ Connected to MySQL database');
});

// ---------------- VALIDACIONES ----------------
const validarTexto = [
  body("texto")
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage("Texto debe tener entre 1 y 50 caracteres"),
];

const validarId = [
  param("id").isInt({ min: 1 }).withMessage("ID debe ser un número positivo"),
];

// ---------------- CRUD ----------------

// CREATE
app.post("/crud", validarTexto, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { texto } = req.body;

  const sql = "INSERT INTO crud (texto) VALUES (?)";
  db.query(sql, [texto], (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: "Error al insertar" });
    }
    res.status(201).json({ msg: "Insertado", id: result.insertId });
  });
});

// READ ALL
app.get("/crud", (req, res) => {
  db.query("SELECT * FROM crud", (err, rows) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: "Error al obtener datos" });
    }
    res.json(rows);
  });
});

// UPDATE
app.put("/crud/:id", [...validarId, ...validarTexto], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { texto } = req.body;

  const sql = "UPDATE crud SET texto=? WHERE id=?";
  db.query(sql, [texto, req.params.id], (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: "Error al actualizar" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ msg: "Registro no encontrado" });
    }
    res.json({ msg: "Actualizado" });
  });
});

// DELETE
app.delete("/crud/:id", validarId, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const sql = "DELETE FROM crud WHERE id=?";
  db.query(sql, [req.params.id], (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: "Error al eliminar" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ msg: "Registro no encontrado" });
    }
    res.json({ msg: "Eliminado" });
  });
});

// ---------------- ERROR HANDLERS ----------------
// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ error: "Error interno del servidor" });
});

// ---------------- SERVIDOR ----------------
const PORT = 3000;
const server = app.listen(PORT, () => {
  console.info(`🚀 Servidor corriendo en puerto ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n⚠️  Cerrando servidor...');
  server.close(() => {
    db.end((err) => {
      if (err) console.error('Error cerrando DB:', err);
      console.log('✅ Servidor cerrado correctamente');
      process.exit(err ? 1 : 0);
    });
  });
});