function redirectToLogin() {
    window.location.href = "login.html";
}

function redirectToRegister() {
    window.location.href = "index.html";
}

function showAppInfo() {
    alert("EcoCyclo é um aplicativo voltado para ajudar na reciclagem e preservação ambiental.");
}

function requestCollection() {
    alert("Solicitação de coleta residencial enviada!");
}

function showMyCollections() {
    alert("Aqui estão suas coletas agendadas.");
}

function callCollectors() {
    alert("Solicitação de coletores enviada!");
}

function contactSupport() {
    alert("Por favor, entre em contato com o suporte pelo e-mail: suporte@ecocyclo.com");
}

function loginWithGoogle() {
    alert("Redirecionando para login com Google...");
}

function loginWithFacebook() {
    alert("Redirecionando para login com Facebook...");
}


require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Configuração do MySQL
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Rota para registrar um novo usuário
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.execute(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hashedPassword]
    );

    res.status(201).json({ message: 'Usuário registrado com sucesso!', userId: result.insertId });
  } catch (err) {
    res.status(400).json({ error: 'Erro ao registrar usuário', details: err.message });
  }
});

// Rota para login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Senha incorreta' });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login bem-sucedido', token });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor', details: err.message });
  }
});

// Rota protegida
app.get('/protected', (req, res) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token inválido' });
    res.json({ message: 'Acesso concedido', userId: decoded.id });
  });
});

// Porta do Servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
