const express = require("express");
const crypto = require("crypto-js");
const dotenv = require("dotenv");
const logger = require("morgan");
const cors = require("cors");
const qs = require("querystring");
const axios = require("axios");
const mongoose = require("mongoose");
const cron = require("node-cron");
const fs = require("fs");
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
console.log("App Loaded");

// Middleware for logging requests
app.use(logger("dev"));

// Middleware to parse JSON
app.use(express.json());

app.use(
  cors({
    origin: "https://sso-app.clingy.app", // Explicitly allow your frontend domain
    credentials: true, // Allow credentials (cookies, authorization headers)
    methods: ["GET", "POST", "OPTIONS"], // Explicitly specify allowed methods
    allowedHeaders: ["Content-Type", "x-sso-session"], // Allowed custom headers
  })
);

app.options("/api/sso/ghl", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "https://sso-app.clingy.app");
  res.setHeader("Access-Control-Allow-Credentials", "true"); // Ensure it's a string "true"
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-sso-session");
  res.status(204).send(); // Send a 204 No Content response for OPTIONS
});

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
    console.error("No GHL SSO session key provided.");
    return res.status(401).json({
      error: "Unauthorized: Missing SSO session key.",
    });
  }

  try {
    // Decrypt the session key using AES
    const decryptedSession = crypto.AES.decrypt(
      encryptedSession,
      process.env.GHL_SSO_KEY
    ).toString(crypto.enc.Utf8); // Ensure the output is in UTF-8 format

    if (!decryptedSession) {
      throw new Error("Failed to decrypt session");
    }

    req.user = JSON.parse(decryptedSession); // Parse decrypted session into user data
    next(); // Proceed to the next middleware/route handler
  } catch (err) {
    console.warn(`Invalid GHL SSO session key: ${err.message}`);
    console.error(err);
    return res.status(401).json({
      error: "Unauthorized: Invalid SSO session key.",
    });
  }
}
app.get("/", (req, res) => {
  res.send("Hello, World!");
});
// Controller logic for '/api/sso/ghl'
app.get("/api/sso/ghl", ghlSsoGuard, (req, res) => {
  console.debug("getUserInfo", req.user);

  if (!req.user) {
    return res.status(401).json({
      error: "Unauthorized: No user information found.",
    });
  }

  res.json(req.user); // Send user data as JSON response
});

// OAuth callback endpoint
app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  if (!code)
    return res.status(400).send("No OAuth Authorization Code received.");

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

    // Delete existing records with the same companyId
    await OAuthCredentials.deleteMany({ companyId });

    // Save new OAuth credentials
    const oauthCredentials = new OAuthCredentials({
      access_token,
      refresh_token,
      expires_in,
      userId,
      locationId,
      companyId,
    });

    await oauthCredentials.save();

    return res.redirect(process.env.GHL_THANK_YOU_PAGE_URL);
  } catch (error) {
    console.error("❌ Error during OAuth token exchange:", error);
    return res.status(500).send("Error during OAuth token exchange");
  }
});

/**
 * Function to exchange authorization code for an access token
 */
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
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    if (response.data?.access_token) return response.data;
    throw new Error("Failed to obtain access token");
  } catch (error) {
    console.error("❌ Error exchanging code for access token:", error);
    throw error;
  }
}

/**
 * Function to refresh the access token
 */
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
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    if (response.data?.access_token) return response.data;
    throw new Error("Failed to refresh access token");
  } catch (error) {
    console.error("❌ Error refreshing access token:", error);
    throw error;
  }
}

/**
 * ⏰ Scheduled Job to Check Token Expiration (Runs Every 5 Minutes)
 * ✅ ADDED: This replaces the `setTimeout` method
 */
cron.schedule("0 0 * * *", async () => {
  console.log("🔄 Checking for expired tokens...");

  const currentTime = Math.floor(Date.now() / 1000); // Get current time in seconds

  try {
    const oauthCredentialsList = await OAuthCredentials.find({});

    for (const credential of oauthCredentialsList) {
      const tokenExpiryTime =
        credential.created_at.getTime() / 1000 + credential.expires_in;

      // Refresh token 24 hours before expiration
      if (currentTime >= tokenExpiryTime - 86400) {
        // 86400 seconds = 24 hours
        console.log(
          `⚠️ Token for companyId: ${credential.companyId} is expiring within 24 hours, refreshing...`
        );

        try {
          const newCredentials = await refreshAccessToken(
            credential.refresh_token
          );

          await OAuthCredentials.updateOne(
            { refresh_token: credential.refresh_token },
            { $set: newCredentials }
          );

          console.log("✅ Access token refreshed successfully.");
        } catch (error) {
          console.error("❌ Error refreshing access token:", error);
        }
      } else {
        console.log(
          `✅ Token is still valid for companyId: ${credential.companyId}`
        );
      }
    }
  } catch (error) {
    console.error("❌ Error checking token expiration:", error);
  }
});

// API to get location access token using companyId and locationId
app.post("/api/get-location-token", async (req, res) => {
  const { companyId, locationId } = req.body;

  if (!companyId || !locationId) {
    return res
      .status(400)
      .json({ message: "companyId and locationId are required" });
  }

  try {
    // Step 1: Get the access token for the agency (company)
    const agencyTokens = await OAuthCredentials.findOne({ companyId });

    if (!agencyTokens) {
      return res.status(404).json({
        message: "Agency tokens not found for the provided companyId",
      });
    }

    // Step 2: Use the agency access token as a header to fetch the location access token
    const url = "https://services.leadconnectorhq.com/oauth/locationToken";
    const response = await axios.post(
      url,
      qs.stringify({ companyId, locationId }),
      {
        headers: {
          Version: "2021-07-28",
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
          Authorization: `Bearer ${agencyTokens.access_token}`, // Using the agency access token as Bearer token
        },
      }
    );

    const data = response.data;

    if (response.status === 201) {
      // Return the location access token in the response
      return res.json(data);
    } else {
      return res
        .status(response.status)
        .json({ message: "Failed to fetch location token", details: data });
    }
  } catch (error) {
    console.error("Error getting location token:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// API endpoint to fetch token and send it as response
app.post("/api/store-token", async (req, res) => {
  const { locationId } = req.body; // Get locationId from the frontend request

  if (!locationId) {
    return res.status(400).json({ error: "Location ID is required" });
  }

  try {
    // Fetch OAuth credentials from the database
    const oauthCredentials = await OAuthCredentials.findOne({});
    if (!oauthCredentials) {
      return res
        .status(400)
        .json({ error: "OAuth credentials not found in database" });
    }

    const { access_token } = oauthCredentials;

    // Make a request to get the location token using axios
    const response = await axios.post(
      `${process.env.GHL_API_DOMAIN}/oauth/locationToken`,
      qs.stringify({ locationId }),
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );

    if (response.status === 201) {
      res.json({ locationToken: response.data.access_token });
    } else {
      res
        .status(response.status)
        .json({ message: "Failed to get location token" });
    }
  } catch (error) {
    console.error("Error getting location token:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Set the server to listen on the specified port
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
