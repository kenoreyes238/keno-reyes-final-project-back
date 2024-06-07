const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
const port = process.env.PORT; 

const corsOptions = {
  origin: 'http://localhost:3000',
  credentials: true,
  'access-control-allow-credentials': true,
  optionSuccessStatus: 200,
};

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use(express.json());

app.use(require('cookie-parser')());

app.use(async (req, res, next) => {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (err) {
    console.log(err)
    if (req.db) req.db.release();
    throw err;
  }
});

app.post('/register', async function (req, res) {
  try {
    const { password, email } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const [users] = await req.db.query(
      `INSERT INTO users (Email, password)
      VALUES (:email, :hashedPassword);`,
      { email, hashedPassword });

    const jwtEncodedUser = jwt.sign(
      { userId: users.insertId, ...req.body },
      process.env.JWT_KEY
    );

    res.json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    console.log('error', err);
    res.json({ err, success: false });
  }
});

app.post('/login', async function (req, res) {
  try {
    const { email, password: userEnteredPassword } = req.body;
    const [[users]] = await req.db.query(`SELECT * FROM users WHERE email = :email`, { email });
    if (!users) {
      return res.json({ error: 'Email not found', success: false });
    }
    const hashedPassword = `${users.password}`;
    const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);
    if (passwordMatches) {
      const payload = {
        userId: users.id,
        email: users.email
      };
      const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);

      res.cookie('jwtToken', jwtEncodedUser, {httpOnly: true});
      return res.json({ jwt: jwtEncodedUser, success: true });
    } else {
      return res.json({ error: 'Password is wrong', success: false });
    }
  } catch (err) {
    console.log('Error in /login', err);
    return res.status(500).json({ error: 'Internal server error', success: false });
  }
});

app.get('/products', async (req, res) => {
  try {
      const [rows] = await req.db.query('SELECT * FROM products WHERE deleted_flag = 0');
      res.json(rows);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/addProduct', async (req, res) => {
  try {
    const { 
      name, 
      price, 
      quantity, 
      amount 
    } = req.body;

    const query = await req.db.query(
      `INSERT INTO products (name, price, quantity, amount, deleted_flag) 
      VALUES (:name, :price, :quantity, :amount, 0)`, 
      {
        name,
        price,
        quantity,
        amount
    });

    res.json({ success: true, message: 'Item successfully added', data: null});
  } catch (err) {
    res.json({success: false, message: 'Failed to add item', data: null})
  }
});

app.put('/editProduct/:id', async function(req,res) {
  try {
    const { id } = req.params;
    const { name, price, quantity, amount } = req.body;
    await req.db.query(
      `UPDATE products SET name = ?, price = ?, quantity = ?, amount = ? WHERE id = ?`,
      [name, price, quantity, amount, id]
    );
    res.json({ success: true, message: 'Item successfully updated'});
  } catch (err) {
    console.log(err);
    res.status(500).json({ success: false, message: 'Failed to update item'});
  }
});

app.delete('/deleteProduct/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await req.db.query(`UPDATE products SET deleted_flag = 1 WHERE id = ?`, [id]);
    res.json({ success: true, message: 'Item successfully deleted' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ success: false, message: 'Failed to delete item' });
  }
});

app.post('/logout', function (req, res) {
  try {
    res.clearCookie('jwtToken'); // Clear the cookie named 'jwtToken'

    res.json({ success: true });
  } catch (error) {
    console.error('Error during sign-out:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use(async function verifyJwt(req, res, next) {
  const { authorization: authHeader } = req.headers;
  
  if (!authHeader) res.json('Invalid authorization, no authorization headers');

  const [scheme, jwtToken] = authHeader.split(' ');

  if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');

  try {
    const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);

    req.user = decodedJwtObject;
  } catch (err) {
    console.log(err);
    if (
      err.message && 
      (err.message.toUpperCase() === 'INVALID TOKEN' || 
      err.message.toUpperCase() === 'JWT EXPIRED')
    ) {

      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);
    } else {

      throw((err.status || 500), err.message);
    }
  }

  await next();
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
})