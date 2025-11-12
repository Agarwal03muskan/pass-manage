require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path'); // Import the path module

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// PostgreSQL connection pool
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Database connected successfully at:', res.rows[0].now);
    }
});

// Encryption functions for password vault data
// **IMPORTANT:  Ensure ENCRYPTION_KEY is 32 bytes (256 bits) for AES-256-GCM**
// If ENCRYPTION_KEY is not set in .env, generate a secure one.  NEVER hardcode this directly.
let ENCRYPTION_KEY;

if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length === 64) { // 64 hex chars = 32 bytes
  ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
} else {
  console.warn("ENCRYPTION_KEY not found in .env or invalid length. Generating a new one.  This is only suitable for development.  Use a secure key for production.");
  ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex'); // Generate a new key
  console.log("Generated ENCRYPTION_KEY (DO NOT COMMIT THIS TO REPOSITORY):", ENCRYPTION_KEY);  // Show the generated key (development only)
}

const algorithm = 'aes-256-gcm';

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag.toString('hex')
    };
}

function decrypt(encryptedObj) {
    try {
      const decipher = crypto.createDecipheriv(
          algorithm,
          Buffer.from(ENCRYPTION_KEY, 'hex'),
          Buffer.from(encryptedObj.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(encryptedObj.authTag, 'hex'));
      let decrypted = decipher.update(encryptedObj.encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      console.error("Decryption error:", error);
      // Handle decryption failures (e.g., invalid key, corrupted data)
      return null;  // Or throw an error, depending on your needs
    }
}

// JWT Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ==================== AUTH ROUTES ====================

// Register new user
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, fullName } = req.body;

    try {
        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // Check if user already exists
        const userCheck = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user
        const result = await pool.query(
            'INSERT INTO users (username, email, password, full_name) VALUES ($1, $2, $3, $4) RETURNING id, username, email, full_name, created_at',
            [username, email, hashedPassword, fullName || null]
        );

        const user = result.rows[0];

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                fullName: user.full_name,
                createdAt: user.created_at
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Validation
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Find user
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                fullName: user.full_name,
                createdAt: user.created_at
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Get current user info
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, email, full_name, created_at, last_login FROM users WHERE id = $1',
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== PASSWORD VAULT ROUTES ====================

// Get all passwords for user
app.get('/api/passwords', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM passwords WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );

        // Decrypt passwords
        const passwords = result.rows.map(row => {
            try {
                const decryptedPassword = decrypt({
                    iv: row.password_iv,
                    encryptedData: row.password_encrypted,
                    authTag: row.password_auth_tag
                });

                if (decryptedPassword === null) { // Check for decryption errors
                  console.warn("Could not decrypt password for ID:", row.id);
                  return null;  // Skip this password
                }

                return {
                    id: row.id,
                    entityName: row.entity_name,
                    username: row.username,
                    password: decryptedPassword,
                    category: row.category,
                    notes: row.notes,
                    dateAdded: row.created_at,
                    updatedAt: row.updated_at
                };
            } catch (err) {
                console.error('Decryption error for password ID:', row.id, err);
                return null;
            }
        }).filter(p => p !== null);  // Remove any passwords that failed to decrypt

        res.json({ passwords });
    } catch (error) {
        console.error('Get passwords error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add new password
app.post('/api/passwords', authenticateToken, async (req, res) => {
    const { entityName, username, password, category, notes } = req.body;

    try {
        // Validation
        if (!entityName || !username || !password) {
            return res.status(400).json({ error: 'Entity name, username, and password are required' });
        }

        // Encrypt password
        const encrypted = encrypt(password);

        // Insert password
        const result = await pool.query(
            `INSERT INTO passwords (user_id, entity_name, username, password_encrypted, password_iv, password_auth_tag, category, notes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, entity_name, username, category, notes, created_at`,
            [
                req.user.id,
                entityName,
                username,
                encrypted.encryptedData,
                encrypted.iv,
                encrypted.authTag,
                category || 'other',
                notes || null
            ]
        );

        const savedPassword = result.rows[0];

        res.status(201).json({
            message: 'Password saved successfully',
            password: {
                id: savedPassword.id,
                entityName: savedPassword.entity_name,
                username: savedPassword.username,
                password: password, // Return decrypted for immediate use
                category: savedPassword.category,
                notes: savedPassword.notes,
                dateAdded: savedPassword.created_at
            }
        });
    } catch (error) {
        console.error('Add password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update password
app.put('/api/passwords/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { entityName, username, password, category, notes } = req.body;

    try {
        // Check if password belongs to user
        const checkResult = await pool.query(
            'SELECT id FROM passwords WHERE id = $1 AND user_id = $2',
            [id, req.user.id]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Password not found' });
        }

        // Encrypt new password if provided
        let updateQuery, updateParams;
        
        if (password) {
            const encrypted = encrypt(password);
            updateQuery = `UPDATE passwords 
                          SET entity_name = $1, username = $2, password_encrypted = $3, 
                              password_iv = $4, password_auth_tag = $5, category = $6, notes = $7, 
                              updated_at = CURRENT_TIMESTAMP
                          WHERE id = $8 AND user_id = $9
                          RETURNING *`;
            updateParams = [entityName, username, encrypted.encryptedData, encrypted.iv, 
                           encrypted.authTag, category, notes, id, req.user.id];
        } else {
            updateQuery = `UPDATE passwords 
                          SET entity_name = $1, username = $2, category = $3, notes = $4, 
                              updated_at = CURRENT_TIMESTAMP
                          WHERE id = $5 AND user_id = $6
                          RETURNING *`;
            updateParams = [entityName, username, category, notes, id, req.user.id];
        }

        const result = await pool.query(updateQuery, updateParams);
        const updated = result.rows[0];

        // Decrypt password for response
        const decryptedPassword = decrypt({
            iv: updated.password_iv,
            encryptedData: updated.password_encrypted,
            authTag: updated.password_auth_tag
        });

        res.json({
            message: 'Password updated successfully',
            password: {
                id: updated.id,
                entityName: updated.entity_name,
                username: updated.username,
                password: decryptedPassword,
                category: updated.category,
                notes: updated.notes,
                dateAdded: updated.created_at,
                updatedAt: updated.updated_at
            }
        });
    } catch (error) {
        console.error('Update password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete password
app.delete('/api/passwords/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query(
            'DELETE FROM passwords WHERE id = $1 AND user_id = $2 RETURNING id',
            [id, req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Password not found' });
        }

        res.json({ message: 'Password deleted successfully' });
    } catch (error) {
        console.error('Delete password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// --- Table Creation Code (Use with CAUTION - Development Only) ---
async function createTables() {
    const { Client } = require('pg'); // Import the Client class

    const client = new Client({  // Create a new client for the table creation
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
    });

    try {
        await client.connect();

        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                full_name VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS passwords (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
                entity_name VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                password_encrypted TEXT NOT NULL,
                password_iv VARCHAR(255) NOT NULL,
                password_auth_tag VARCHAR(255) NOT NULL,
                category VARCHAR(50) DEFAULT 'other',
                notes TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE
            );
        `);
        // Optional indexes
        await client.query('CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id);');
        await client.query('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);');
        await client.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);');

        console.log("Tables created (or already exist).");

    } catch (err) {
        console.error("Error creating tables:", err);
    } finally {
        await client.end();  // Close the client
    }
}

// Start server
app.listen(PORT, async () => {
    console.log(`VaultGuard server running on port ${PORT}`);
    console.log(`Server listening on: http://localhost:${PORT}`);
    await createTables(); // Call the function here to create the tables if they don't exist.  ***FOR DEVELOPMENT/TESTING ONLY***
});