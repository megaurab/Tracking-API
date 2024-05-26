
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pg from "pg";
import bodyParser from "body-parser";
import nodemailer from "nodemailer";
import env from "dotenv";

const app = express();
app.use(express.json());
env.config();

app.use(bodyParser.urlencoded({ extended: true }));

// PostgreSQL configuration
const pool = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

pool.connect();
// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.ADMIN_EMAIL,
    pass: process.env.ADMIN_PASSWORD,
  },
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token1 = req.headers["authorization"];
  const token = token1.split(" ")[1];

  if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

    req.userRole = decoded.role;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).send({ auth: false, message: 'Access restricted to admins only.' });
  }
  next();
};

// User Registration
app.post('/register', async (req, res) => {
  const username = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const role = req.body.role;

  try {
    const checkResult = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.status(500).send('Error during registration.');
    } else {
      bcrypt.hash(password, 10, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          const result = await pool.query(
            "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *",
            [username, email, hash, role]
          );
          res.status(200).json(result.rows);
        }
      })
    }
  } catch (err) {
    console.log(err);
  }
});

// User Login
app.post('/login', async (req, res) => {
  const useremail = req.body.email;
  const password = req.body.password;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [useremail]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashPassword = user.password;

      bcrypt.compare(password, storedHashPassword, (err, result) => {
        if (err) {
          return res.status(401).send('Invalid password.');
        } else {
          if (result) {
            const token = jwt.sign({ id: user.email, role: user.role }, JWT_SECRET);
            res.status(200).send({ auth: true, token: token });
          }
        }
      })
    }

  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).send('Error during login.');
  }
});

// CRUD Operations for Products

// Create Product
app.post('/createproducts', verifyToken, isAdmin, async (req, res) => {
  const name = req.body.name;
  const description = req.body.description;
  const trackingNumber = req.body.trackingNumber;
  try {
    await pool.query('INSERT INTO products (name, description, tracking_number) VALUES ($1, $2, $3)', [name, description, trackingNumber]);
    res.status(201).send('Product created successfully.');
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).send('Error creating product.');
  }
});

// RETRIEVE ALL PRODUCTS
app.get('/getallproducts', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error retrieving products:', error);
    res.status(500).send('Error retrieving products.');
  }
});

// UPDATE PRODUCT DETAILS
app.put('/products/:id', verifyToken, isAdmin, async (req, res) => {
  const id = req.params.id;
  const name = req.body.name;
  const description = req.body.description;
  const tracking = req.body.tracking;

  try {
    const result = await pool.query(
      'UPDATE products SET name = $1, description = $2, tracking_number = $3 WHERE id = $4 RETURNING *',
      [name, description, tracking, id]
    );

    if (result.rowCount === 0) {
      res.status(404).send('Product not found.');
    } else {
      res.status(200).json(result.rows[0]);
    }
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).send('Error updating product.');
  }
});

// UPDATE SPECIFIC-PRODUCT DETAILS
// Patch product

app.patch('/products/:id', verifyToken, isAdmin, async (req, res) => {
  const id = req.params.id;
  const name = req.body.name;
  const description = req.body.description;
  const tracking = req.body.tracking;

  const fp = await pool.query("SELECT id, name, description, tracking_number FROM products WHERE id = $1", [id]);
  if (fp.rows.length == 0) {
    res.status(404).send('Product not found.');
  }
  const user = fp.rows[0];

  const updated_name = name || user.name;
  const updated_description = description || user.description;
  const updated_tracking = tracking || user.tracking_number;



  try {
    const result = await pool.query(
      'UPDATE products SET name = $1, description = $2, tracking_number = $3 WHERE id = $4 RETURNING *',
      [updated_name, updated_description, updated_tracking, id]
    );
    res.status(200).json(result.rows[0]);

  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).send('Error updating product.');
  }
});

// DELETE PARTICULAR PRODUCT
app.delete('/products/:id', verifyToken, isAdmin, async (req, res) => {

  const id = req.params.id;
  try {
    await pool.query('DELETE FROM products WHERE id = $1', [id]);
    res.status(200).send('Product deleted successfully.');
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).send('Error deleting product.');
  }
});

// ADD TRACKING EVENTS
app.post('/tracking', verifyToken, isAdmin, async (req, res) => {
  const productId = req.body.productId;
  const status = req.body.status;
  const location = req.body.location;
  const user = "customer";

  try {
    await pool.query('INSERT INTO tracking_events (product_id, status, location, created_at) VALUES ($1, $2, $3, NOW())', [productId, status, location]);

    // SEND EMAIL NOTIFICATION
    const userResult = await pool.query('SELECT email FROM users WHERE role = $1', [user]);
    const emails = userResult.rows.map(row => row.email);

    const mailOptions = {
      from: process.env.ADMIN_EMAIL,
      to: emails,
      subject: 'Tracking Event Created',
      text: `A new tracking event has been created for product ID ${productId} with status ${status} at location ${location}.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent:', info.response);
      }
    });
    res.status(201).send('Tracking event created successfully.');
  } catch (error) {
    console.error('Error creating tracking event:', error);
    res.status(500).send('Error creating tracking event.');
  }
});

// Retrieve Tracking Events by Product ID
app.get('/tracking/:productId', verifyToken, async (req, res) => {
  const productId = req.params.productId;
  try {
    const result = await pool.query('SELECT * FROM tracking_events WHERE product_id = $1', [productId]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error retrieving tracking events:', error);
    res.status(500).send('Error retrieving tracking events.');
  }
});

// Update All-Tracking Event
app.put('/tracking/:id', verifyToken, isAdmin, async (req, res) => {

  const id = req.params.id;
  const status = req.body.status;
  const location = req.body.location;
  const user = "customer";

  try {
    await pool.query('UPDATE tracking_events SET status = $1, location = $2, created_at = NOW() WHERE product_id = $3', [status, location, id]);

    // EMAIL NOTIFICATION

    const userResult = await pool.query('SELECT email FROM users WHERE role = $1', [user]);
    const emails = userResult.rows.map(row => row.email);

    const mailOptions = {
      from: process.env.ADMIN_EMAIL,
      to: emails,
      subject: 'Tracking Event Updated',
      text: `Tracking event ID ${id} has been updated with status ${status} at location ${location}.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent:', info.response);
      }
    });
    res.status(200).send('Tracking event updated successfully.');
  } catch (error) {
    console.error('Error updating tracking event:', error);
    res.status(500).send('Error updating tracking event.');
  }
});

// PATCH TRACKING EVENT

app.patch('/tracking/:id', verifyToken, isAdmin, async (req, res) => {
  const id = req.params.id;
  const status = req.body.status;
  const location = req.body.location;
  const user1 = "customer";

  const fp = await pool.query("SELECT status, location FROM tracking_events WHERE product_id = $1", [id]);
  if (fp.rows.length == 0) {
    res.status(404).send('Product not found.');
  }
  const user = fp.rows[0];

  const updated_status = status || user.status;
  const updated_location = location || user.location;

  try {
    const result = await pool.query(
      'UPDATE tracking_events SET status = $1, location = $2, created_at = NOW() WHERE product_id = $3 RETURNING *',
      [updated_status, updated_location, id]);

    // EMAIL NOTIFICATION
    const userResult = await pool.query('SELECT email FROM users WHERE role = $1', [user1]);
    const emails = userResult.rows.map(row => row.email);

    const mailOptions = {
      from: process.env.ADMIN_EMAIL,
      to: emails,
      subject: 'Tracking Event Updated',
      text: `Tracking event ID ${id} has been updated with status ${status} at location ${location}.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent:', info.response);
      }
    });
    res.status(200).send('Tracking event updated successfully.');

  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).send('Error updating product.');
  }
});

// Delete Tracking Event
app.delete('/tracking/:id', verifyToken, isAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM tracking_events WHERE product_id = $1', [id]);
    res.status(200).send('Tracking event deleted successfully.');
  } catch (error) {
    console.error('Error deleting tracking event:', error);
    res.status(500).send('Error deleting tracking event.');
  }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} `);
})



