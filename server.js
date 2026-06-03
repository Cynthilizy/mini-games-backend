import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import "dotenv/config";
import cors from "cors";
import fs from "fs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import passport from "passport";
import FacebookStrategy from "passport-facebook";
import GoogleStrategy from "passport-google-oauth20";
import rateLimit from "express-rate-limit";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const { Pool } = pg;

const app = express();
const port = 5005;
const saltingRounds = 10;

const db = new Pool({
  user: process.env.USERNAME,
  host: process.env.HOSTNAME,
  database: process.env.DB_NAME,
  password: process.env.PASSWORD,
  port: process.env.DB_PORT,
});

//middle ware
app.use(
  cors({
    origin: ["http://localhost:3000"],
  }),
);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());

app.use(passport.initialize());

app.use("/", express.static(path.join(__dirname, "dist")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "dist/index.html"));
});

function auth(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Not logged in" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // max 10 attempts per IP
  message: {
    error: "Too many login attempts. Try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

async function createUniqueUsername(db) {
  let username;
  let exists = true;

  while (exists) {
    username = generateUsername();

    const check = await db.query("SELECT 1 FROM gamers WHERE username = $1", [
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
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const providerId = profile.id;
        const email = profile.emails?.[0]?.value;

        let result = await db.query(
          "SELECT * FROM gamers WHERE provider = $1 AND provider_id = $2",
          ["google", providerId],
        );

        let user = result.rows[0];

        if (!user) {
          const username = await createUniqueUsername(db);
          const newUser = await db.query(
            `INSERT INTO gamers (username, email, provider, provider_id, password)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [username, email, "google", providerId, null],
          );

          user = newUser.rows[0];
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    },
  ),
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: "/auth/facebook/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const providerId = profile.id;
        const email = profile.emails?.[0]?.value;

        if (!email) {
          return done(new Error("No email provided by provider"), null);
        }

        let result = await db.query(
          "SELECT * FROM gamers WHERE provider = $1 AND provider_id = $2",
          ["facebook", providerId],
        );

        let user = result.rows[0];

        if (!user) {
          const username = await createUniqueUsername(db);
          const newUser = await db.query(
            `INSERT INTO gamers (username, email, provider, provider_id, password)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [username, email, "facebook", providerId, null],
          );

          user = newUser.rows[0];
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    },
  ),
);

const adjectives = [
  "sleepy",
  "chaotic",
  "tiny",
  "wild",
  "cosmic",
  "sneaky",
  "lucky",
  "greedy",
  "silent",
  "funky",
];

const animals = [
  "panda",
  "fox",
  "llama",
  "otter",
  "cat",
  "sloth",
  "raccoon",
  "wolf",
  "duck",
  "penguin",
];

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    session: false,
  }),
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user.id,
        email: req.user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "6h" },
    );

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
    });

    res.redirect("http://localhost:3000");
  },
);

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    session: false,
  }),
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user.id,
        email: req.user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "6h" },
    );

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
    });

    res.redirect("http://localhost:3000");
  },
);

app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query(
      "SELECT * FROM gamers WHERE email = $1 AND deleted_at IS NULL AND provider = 'local'",
      [email],
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "6h",
      },
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    });

    res.json({ message: "Login successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM gamers WHERE email = $1", [
      email,
    ]);

    const user = result.rows[0];

    // Active user
    if (user && user.deleted_at === null) {
      return res.status(409).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, saltingRounds);

    const username = await createUniqueUsername(db);

    // Restore deleted user
    if (user && user.deleted_at !== null) {
      await db.query(
        `UPDATE gamers 
         SET username = $1,
             password = $2,
             provider = 'local',
             provider_id = NULL,
             deleted_at = NULL
         WHERE email = $3`,
        [username, hashedPassword, email],
      );

      return res.json({ message: "Account restored" });
    }

    // New user
    await db.query(
      `INSERT INTO gamers (
        username,
        email,
        password,
        provider,
        provider_id,
        deleted_at
      ) VALUES ($1, $2, $3, 'local', NULL, NULL)`,
      [username, email, hashedPassword],
    );

    return res.status(201).json({ message: "Account created" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/logout", auth, (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    sameSite: "lax",
  });
  res.json({ message: "Logout successful" });
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
);

app.get(
  "/auth/facebook",
  passport.authenticate("facebook", {
    scope: ["email"],
    session: false,
  }),
);

app.put("/change-username", auth, async (req, res) => {
  const { newUsername } = req.body;
  const email = req.user.email;

  try {
    const result = await db.query(
      `UPDATE gamers
       SET username = $1
       WHERE email = $2
       AND deleted_at IS NULL
       RETURNING *`,
      [newUsername, email],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.put("/change-password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const email = req.user.email;

  try {
    const result = await db.query(
      `SELECT *
       FROM gamers
       WHERE email = $1
       AND provider = 'local'
       AND deleted_at IS NULL`,
      [email],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, saltingRounds);

    await db.query(
      `UPDATE gamers
       SET password = $1
       WHERE email = $2
       AND provider = 'local'
       AND deleted_at IS NULL`,
      [hashedPassword, email],
    );

    res.json({ message: "Password updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.put("/delete-account", auth, async (req, res) => {
  const email = req.user.email;

  try {
    await db.query(
      `UPDATE gamers
       SET deleted_at = NOW()
       WHERE email = $1
       AND deleted_at IS NULL`,
      [email],
    );

    res.clearCookie("token");
    res.json({ message: "Account soft deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/flags", auth, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM flags");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/capitals", auth, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM capitals");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
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
