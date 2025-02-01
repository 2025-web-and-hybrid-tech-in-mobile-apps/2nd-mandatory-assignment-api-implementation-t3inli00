const express = require("express");
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json()); // for parsing application/json

// ------ Dependencies ------//
const passport = require("passport");
const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");
const jwt = require("jsonwebtoken");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

// Secret key for JWT
const SECRET_KEY = process.env.ACCESS_TOKEN_PRIVATE_KEY || "abcdefghijkmlngpppo12345666";

// Initialize AJV for validation
const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

// User and High Score Data Stores
const users = [];
const highScores = [{ level: "A1", userHandle: "DukeNukem", score: 12345, timestamp: "2021-04-01T12:00:00Z" },
  { level: "A1", userHandle: "DukeNukem", score: 12346, timestamp: "2021-04-01T12:00:00Z" },
  { level: "A1", userHandle: "DukeNukem", score: 12343, timestamp: "2021-04-01T12:00:00Z" }
];

// Passport JWT Strategy
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: SECRET_KEY,
    },
    (payload, done) => {
      const user = users.find((user) => user.userHandle === payload.userHandle);
      if (user) {
        return done(null, user);
      }
      return done(null, false);
    }
  )
);
app.use(passport.initialize());

// User Signup Endpoint
app.post("/signup", (req, res) => {
  const { userHandle, password } = req.body;

  //user Validation
  if (!userHandle || !password || userHandle.length < 6 || password.length < 6) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  users.push({ userHandle, password });
  return res.status(201).json({ message: "User registered successfully" });
});

// User Login Endpoint
app.post("/login", (req, res) => {
  const { userHandle, password } = req.body;

  //checking for additional fields
  const allowedFields =["userHandle","password"];
  const extraFields =Object.keys(req.body).filter((f) => !allowedFields.includes(f));

  if(extraFields.length >0){return res.status(400).send("Extra field found,Invalid body")}

  if (!userHandle || !password || typeof userHandle !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid request body" });
  }

  const existingUser = users.find((user) => user.userHandle === userHandle);
  if (!existingUser || existingUser.password !== password) {
    return res.status(401).json({ message: "Unauthorized, incorrect username or password" });
  }

  const tokenPayload = { userHandle: existingUser.userHandle };
  const token = jwt.sign(tokenPayload, SECRET_KEY, { expiresIn: "1h" });
  
  return res.status(200).json({jsonWebToken : token });
});

// Post High Score Endpoint
app.post(
  "/high-scores",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    const { level, userHandle, score, timestamp } = req.body;
    
    if (!level || !userHandle || !score || !timestamp) {
      return res.status(400).json({ error: "Missing required fields: level, userHandle, score, or timestamp" });
    }

    const highScore = { level, userHandle, score, timestamp };
    highScores.push(highScore);
    return res.status(201).json({ message: "High score posted successfully", highScore });
  }
);

// Get High Scores Endpoint
app.get("/high-scores",  (req, res) => {
  const { level, page = 1 } = req.query;
  const scoresPerPage = 20;

  if (!level) {
    return res.status(400).json( [] );
  }

  const filteredScores = highScores.filter((score) => score.level == level);
  const sortedScores = filteredScores.sort((a, b) => b.score - a.score);
  const paginatedScores = sortedScores.slice((page - 1) * scoresPerPage, page * scoresPerPage);

  return res.status(200).json( paginatedScores );
});

let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};
