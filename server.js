const express = require("express");
const crypto = require("crypto-js");
const dotenv = require("dotenv");
const logger = require("morgan");
const cors = require("cors");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware for logging requests
app.use(logger("dev"));

// Middleware to parse JSON
app.use(express.json());

// Allow CORS from the iframe's domain
app.use(
  cors({
    origin: "https://sso-app.clingy.app",
    methods: ["GET", "POST"],
  })
);

// GHL SSO Guard middleware
function ghlSsoGuard(req, res, next) {
  const encryptedSession = req.headers["x-sso-session"];

  if (!encryptedSession) {
    console.error(
      "No GHL SSO session key provided, did you forget to include the `x-sso-session` header?"
    );
    return res.status(401).json({
      error: "Unauthorized: Missing SSO session key.",
    });
  }

  try {
    const decryptedSession = crypto.AES.decrypt(
      encryptedSession,
      process.env.GHL_SSO_KEY
    ).toString(crypto.enc.Utf8);

    req.user = JSON.parse(decryptedSession);
    next();
  } catch (err) {
    console.warn(
      `Invalid GHL SSO session key provided, please try again: ${err.message}`
    );
    console.error(err);
    return res.status(401).json({
      error: "Unauthorized: Invalid SSO session key.",
    });
  }
}

// Controller logic for '/api/sso/ghl'
app.get("/api/sso/ghl", ghlSsoGuard, (req, res) => {
  console.debug("getUserInfo", req.user);

  if (!req.user) {
    return res.status(401).json({
      error: "Unauthorized: No user information found.",
    });
  }

  res.json(req.user);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
