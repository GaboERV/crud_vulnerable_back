const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const helmet = require("helmet");
const xss = require("xss-clean");
const { body, param, validationResult } = require("express-validator");
const sanitizeHtml = require("sanitize-html");


const app = express();
app.use(cors());
app.use(express.json());
app.use(helmet());

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
    if (err) return res.status(500).json({ error: "DB Error" });
    res.json({ msg: "Insertado", id: result.insertId });
  });
});

// READ ALL
app.get("/crud", (req, res) => {
  db.query("SELECT * FROM crud", (err, rows) => {
    if (err) return res.status(500).json({ error: "DB Error" });
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
    if (err) return res.status(500).json({ error: "DB Error" });
    if (result.affectedRows === 0) {
      return res.status(404).json({ msg: "No existe" });
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
    if (err) return res.status(500).json({ error: "DB Error" });
    if (result.affectedRows === 0) {
      return res.status(404).json({ msg: "No existe" });
    }
    res.json({ msg: "Eliminado" });
  });
});

// ---------------- SERVIDOR ----------------
const PORT = 3000;
app.listen(PORT, () => {
console.info(`app lista`);
});
