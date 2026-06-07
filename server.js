import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import 'dotenv/config';
import cors from 'cors';
import fs from 'fs';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import FacebookStrategy from 'passport-facebook';
import GoogleStrategy from 'passport-google-oauth20';
import rateLimit from 'express-rate-limit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const { Pool } = pg;

const app = express();
const port = 5005;
const saltingRounds = 10;

const db = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

//middle ware
app.use(
  cors({
    origin: [
      process.env.CLIENT_URL,
      process.env.MINI_GAMES_API_URL,
      process.env.PORTFOLIO_API_URL,
    ],
    credentials: true,
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());

app.use(passport.initialize());

/*app.use('/', express.static(path.join(__dirname, 'dist')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist/index.html'));
});*/

function auth(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // max 10 attempts per IP
  message: {
    error: 'Too many login attempts. Try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const adjectives = [
  'sleepy',
  'Chaotic',
  'Tiny',
  'Wild',
  'Cosmic',
  'Sneaky',
  'Lucky',
  'Greedy',
  'Silent',
  'Funky',
  'Crazy',
  'Dark',
  'Swift',
];

const animals = [
  'Panda',
  'Fox',
  'Llama',
  'Otter',
  'Cat',
  'Sloth',
  'Raccoon',
  'Wolf',
  'Duck',
  'Penguin',
  'Tiger',
  'Eagle',
  'Dragon',
];

function generateUsername() {
  const a = adjectives[Math.floor(Math.random() * adjectives.length)];
  const b = animals[Math.floor(Math.random() * animals.length)];
  const n = Math.floor(Math.random() * 9999);

  return `${a}${b}${n}`;
}

async function createUniqueUsername(db) {
  let username;
  let exists = true;

  while (exists) {
    username = generateUsername();

    const check = await db.query('SELECT 1 FROM gamers WHERE username = $1', [
      username,
    ]);

    exists = check.rows.length > 0;
  }

  return username;
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const providerId = profile.id;
        const provider = 'google';
        const email = profile.emails?.[0]?.value || null;

        // 1. Check if OAuth already exists
        let oauthRes = await db.query(
          `SELECT gamer_id FROM oauth_accounts 
           WHERE provider = $1 AND provider_id = $2`,
          [provider, providerId]
        );

        let gamerId;

        if (oauthRes.rows.length > 0) {
          gamerId = oauthRes.rows[0].gamer_id;
        } else {
          // 2. Create new gamer
          const username = await createUniqueUsername(db);

          const gamerRes = await db.query(
            `INSERT INTO gamers (username, email, password)
             VALUES ($1, $2, $3)
             RETURNING id, username, email`,
            [username, email, null]
          );

          gamerId = gamerRes.rows[0].id;

          // 3. Link OAuth account
          await db.query(
            `INSERT INTO oauth_accounts (gamer_id, provider, provider_id)
             VALUES ($1, $2, $3)`,
            [gamerId, provider, providerId]
          );
        }

        // 4. Load final user
        const userRes = await db.query(
          `SELECT id, username, email FROM gamers WHERE id = $1`,
          [gamerId]
        );

        return done(null, userRes.rows[0]);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const providerId = profile.id;
        const provider = 'facebook';
        const email = profile.emails?.[0]?.value || null;

        // 1. Check if OAuth already exists
        let oauthRes = await db.query(
          `SELECT gamer_id FROM oauth_accounts 
           WHERE provider = $1 AND provider_id = $2`,
          [provider, providerId]
        );

        let gamerId;

        if (oauthRes.rows.length > 0) {
          gamerId = oauthRes.rows[0].gamer_id;
        } else {
          // 2. Create new gamer
          const username = await createUniqueUsername(db);

          const gamerRes = await db.query(
            `INSERT INTO gamers (username, email, password)
             VALUES ($1, $2, $3)
             RETURNING id, username, email`,
            [username, email, null]
          );

          gamerId = gamerRes.rows[0].id;

          // 3. Link OAuth account
          await db.query(
            `INSERT INTO oauth_accounts (gamer_id, provider, provider_id)
             VALUES ($1, $2, $3)`,
            [gamerId, provider, providerId]
          );
        }

        // 4. Load final user
        const userRes = await db.query(
          `SELECT id, username, email FROM gamers WHERE id = $1`,
          [gamerId]
        );

        return done(null, userRes.rows[0]);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET, {
      expiresIn: '6h',
    });

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    res.redirect(process.env.CLIENT_URL);
  }
);

app.get(
  '/auth/facebook/callback',
  passport.authenticate('facebook', { session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET, {
      expiresIn: '6h',
    });

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });

    res.redirect(process.env.CLIENT_URL);
  }
);

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query(
      'SELECT * FROM gamers WHERE email = $1 AND deleted_at IS NULL',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (!user.password) {
      return res.status(401).json({
        error: 'oauth_account',
        message: 'Use Google or Facebook login',
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: '6h',
      }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
    });

    res.json({ message: 'Login successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/register', async (req, res) => {
  const email = req.body?.email;
  const password = req.body?.password;

  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }

  try {
    const result = await db.query('SELECT * FROM gamers WHERE email = $1', [
      email,
    ]);

    const user = result.rows[0];

    // Active user
    if (user && user.deleted_at === null) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, saltingRounds);

    const username = await createUniqueUsername(db);

    // Restore deleted user
    if (user && user.deleted_at !== null) {
      await db.query(
        `UPDATE gamers 
         SET username = $1,
             password = $2,
             deleted_at = NULL
         WHERE email = $3`,
        [username, hashedPassword, email]
      );

      return res.json({ message: 'Account restored' });
    }

    // New user
    await db.query(
      `INSERT INTO gamers (
        username,
        email,
        password,
        deleted_at
      ) VALUES ($1, $2, $3, NULL)`,
      [username, email, hashedPassword]
    );

    return res.status(201).json({
      message: 'Account created',
      user: {
        email,
        username,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/logout', auth, (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
  });
  res.json({ message: 'Logout successful' });
});

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  })
);

app.get(
  '/auth/facebook',
  passport.authenticate('facebook', {
    scope: ['email'],
    session: false,
  })
);

app.put('/change-username', auth, async (req, res) => {
  const { newUsername } = req.body;
  const userId = req.user.id;

  try {
    const result = await db.query(
      `UPDATE gamers
       SET username = $1
       WHERE id = $2
       AND deleted_at IS NULL
       RETURNING id, username, email`,
      [newUsername, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    const result = await db.query(
      `SELECT password
       FROM gamers
       WHERE id = $1
       AND deleted_at IS NULL`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    if (!user.password) {
      return res.status(400).json({
        error: 'oauth_account',
        message: 'This account uses Google/Facebook login',
      });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, saltingRounds);

    await db.query(
      `UPDATE gamers
       SET password = $1
       WHERE id = $2`,
      [hashedPassword, userId]
    );

    res.json({ message: 'Password updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/delete-account', auth, async (req, res) => {
  const userId = req.user.id;

  try {
    await db.query(
      `UPDATE gamers
       SET deleted_at = NOW()
       WHERE id = $1
       AND deleted_at IS NULL`,
      [userId]
    );

    await db.query(`DELETE FROM oauth_accounts WHERE gamer_id = $1`, [userId]);

    res.clearCookie('token', {
      httpOnly: true,
      sameSite: 'lax',
    });

    res.json({ message: 'Account soft deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/flags', auth, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM flags');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/capitals', auth, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM capitals');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

/*app.delete("/delete-account", auth, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query(
      "SELECT * FROM gamers WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    await db.query(
      "DELETE FROM gamers WHERE email = $1",
      [email]
    );

    res.clearCookie("token");
    res.json({ message: "Account deleted" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});*/

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
