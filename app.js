const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000;
//Precisa do responsivo apenas
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "1234",
  database: "chat_app",
};

const pool = mysql.createPool(dbConfig);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get("/register", (req, res) => {
  const filePath = path.join(__dirname, "./pages/registro.html");
  res.sendFile(filePath);
});

app.use(express.static(path.join(__dirname, "public")));

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const connection = await pool.getConnection();

    // Verifica se o usuário já existe no banco de dados
    const [existingUsers] = await connection.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (existingUsers.length > 0) {
      connection.release();
      res.send(
        "<script>alert('Usuário já cadastrado.'); window.location.href='/login';</script>"
      );
      return;
    }

    // Criptografa a senha
    const hashedPassword = await bcrypt.hash(password, 1);

    await connection.execute(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );
    connection.release();

    res.send(
      "<script>alert('Registro concluído com sucesso!'); window.location.href='/login';</script>"
    );
  } catch (error) {
    console.error("Erro ao registrar usuário:", error);
    res.send(
      "<script>alert('Ocorreu um erro ao registrar o usuário. Tente novamente mais tarde.'); window.location.href='/login';</script>"
    );
  }
});

app.get("/login", (req, res) => {
  const filePath = path.join(__dirname, "./pages/login.html");
  res.sendFile(filePath);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      connection.release();
      res.send(
        "<script>alert('Nome de usuário ou senha inválidos.'); window.location.href='/login';</script>"
      );
      return;
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      connection.release();
      res.send(
        "<script>alert('Nome de usuário ou senha inválidos.'); window.location.href='/login';</script>"
      );
      return;
    }

    connection.release();
    res.send("<script>alert('Login bem-sucedido.'); window.location.href='/';</script>");
  } catch (error) {
    console.error("Erro ao fazer login:", error);
    res.send(
      "<script>alert('Erro ao fazer login. Tente novamente mais tarde.'); window.location.href='/login';</script>"
    );
  }
});

app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`);
});
