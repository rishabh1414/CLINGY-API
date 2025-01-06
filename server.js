const express = require("express");
const crypto = require("crypto-js");
const dotenv = require("dotenv");
const logger = require("morgan");
const cors = require("cors");
const qs = require("querystring");
const axios = require("axios");
const mongoose = require("mongoose");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
console.log("App Loaded");

// Middleware for logging requests
app.use(logger("dev"));

// Middleware to parse JSON
app.use(express.json());

// CORS configuration
const corsOptions = {
  origin: "https://sso-app.clingy.app", // Your frontend domain
  methods: ["GET", "POST", "PUT", "DELETE"], // Allowed HTTP methods
  allowedHeaders: ["Content-Type", "Authorization", "x-sso-session"], // Allowed headers
  credentials: true, // Allow credentials (cookies) to be sent
};

app.use(cors(corsOptions));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// OAuth Credentials Schema
const OAuthCredentialsSchema = new mongoose.Schema({
  access_token: String,
  refresh_token: String,
  expires_in: Number, // Expiry time in seconds
  userId: String,
  locationId: String,
  companyId: String,
  created_at: { type: Date, default: Date.now },
});

const OAuthCredentials = mongoose.model(
  "OAuthCredentials",
  OAuthCredentialsSchema
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

// OAuth callback endpoint
app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).send("No OAuth Authorization Code received.");
  }

  try {
    const credentials = await getAccessToken(code);
    const {
      access_token,
      refresh_token,
      expires_in,
      userId,
      locationId,
      companyId,
    } = credentials;

    // Save only important fields to MongoDB
    const oauthCredentials = new OAuthCredentials({
      access_token,
      refresh_token,
      expires_in,
      userId,
      locationId,
      companyId,
    });

    await oauthCredentials.save(); // Save to MongoDB

    // Set up automatic refresh before the token expires (86400 seconds)
    setTokenRefresh(oauthCredentials);

    return res.redirect(process.env.GHL_THANK_YOU_PAGE_URL);
  } catch (error) {
    return res.status(500).send("Error during OAuth token exchange");
  }
});

// Function to exchange the authorization code for an access token
async function getAccessToken(code) {
  const body = qs.stringify({
    client_id: process.env.GHL_CLIENT_ID,
    client_secret: process.env.GHL_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
  });

  try {
    const response = await axios.post(
      `${process.env.GHL_API_DOMAIN}/oauth/token`,
      body,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    if (response.data && response.data.access_token) {
      // Return credentials (access token and refresh token)
      return response.data;
    } else {
      throw new Error("Failed to obtain access token");
    }
  } catch (error) {
    console.error("Error exchanging code for access token:", error);
  }
}

// Function to refresh the access token before it expires
async function setTokenRefresh(oauthCredentials) {
  const refreshTokenBeforeExpiry = oauthCredentials.expires_in - 300; // Refresh 5 minutes before expiration

  setTimeout(async () => {
    try {
      const newCredentials = await refreshAccessToken(
        oauthCredentials.refresh_token
      );
      // Save the new credentials to the database
      await OAuthCredentials.updateOne(
        { refresh_token: oauthCredentials.refresh_token },
        { $set: newCredentials }
      );
      console.log("Access token refreshed successfully.");
    } catch (error) {
      console.error("Error refreshing access token:", error);
    }
  }, refreshTokenBeforeExpiry * 1000); // Set timeout in milliseconds
}

// Function to refresh the access token
async function refreshAccessToken(refresh_token) {
  const body = qs.stringify({
    client_id: process.env.GHL_CLIENT_ID,
    client_secret: process.env.GHL_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token,
  });

  try {
    const response = await axios.post(
      `${process.env.GHL_API_DOMAIN}/oauth/token`,
      body,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    return response.data; // Return new credentials
  } catch (error) {
    console.error("Error refreshing access token:", error);
    throw new Error(`Error refreshing access token: ${error.message}`);
  }
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
