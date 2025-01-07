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

app.use((req, res, next) => {
  console.log("Incoming headers:", req.headers);
  next();
});

// GHL SSO Guard middleware
function ghlSsoGuard(req, res, next) {
  const encryptedSession = req.headers["x-sso-session"];
  console.log(encryptedSession);

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

    // Delete existing records with the same companyId
    await OAuthCredentials.deleteMany({ companyId });

    // Save the new record to MongoDB
    const oauthCredentials = new OAuthCredentials({
      access_token,
      refresh_token,
      expires_in,
      userId,
      locationId,
      companyId,
    });

    await oauthCredentials.save(); // Save the new record

    // Set up automatic refresh before the token expires (86400 seconds)
    setTokenRefresh(oauthCredentials);

    return res.redirect(process.env.GHL_THANK_YOU_PAGE_URL);
  } catch (error) {
    console.error("Error during OAuth token exchange:", error);
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
    const options = {
      method: "POST",
      headers: {
        Version: "2021-07-28",
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Authorization: `Bearer ${agencyTokens.access_token}`, // Using the agency access token as Bearer token
      },
      body: new URLSearchParams({
        companyId,
        locationId,
      }),
    };

    const response = await fetch(url, options);
    const data = await response.json();

    if (response.ok) {
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

    const { access_token, companyId } = oauthCredentials;

    const url = "https://services.leadconnectorhq.com/oauth/locationToken";
    const options = {
      method: "POST",
      headers: {
        Version: "2021-07-28",
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Authorization: `Bearer ${access_token}`, // Get access token from the database
      },
      body: new URLSearchParams({
        companyId: companyId, // Get companyId from the database
        locationId: locationId, // Get locationId from the request body
      }),
    };

    const response = await fetch(url, options);
    const data = await response.json();

    if (response.ok) {
      // Assuming the response contains a field 'c_token' for the access token
      const {
        access_token,
        token_typ,
        expires_in,
        refresh_token,
        scope,
        locationId,
      } = data;

      // Send the token as a response to the client
      return res.status(200).json({
        access_token,
        token_typ,
        expires_in,
        refresh_token,
        scope,
        locationId,
      });
    } else {
      return res
        .status(400)
        .json({ error: "Failed to fetch token", details: data });
    }
  } catch (error) {
    console.error("Error fetching token:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Function to refresh token using refresh_token
async function refreshToken(userId) {
  try {
    // Fetch OAuth credentials from the database
    const credentials = await OAuthCredentials.findOne({ _id: userId });
    if (!credentials) {
      console.error("No credentials found for this user.");
      return;
    }

    const { refresh_token, expires_in } = credentials;
    // Check if token is about to expire in less than an hour (86399 seconds)
    const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
    const expireTime = currentTime + 3600; // One hour before expiration
    const tokenExpiryTime =
      credentials.created_at.getTime() / 1000 + expires_in;

    if (tokenExpiryTime - expireTime <= 0) {
      // Make the API call to refresh the token
      const url = "https://services.leadconnectorhq.com/oauth/token";
      const options = {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          client_id: process.env.GHL_CLIENT_ID,
          client_secret: process.env.GHL_CLIENT_SECRET,
          grant_type: "refresh_token",
          refresh_token: refresh_token,
          user_type: "Company",
        }),
      };

      // Fetch the new access and refresh tokens
      const response = await fetch(url, options);
      const data = await response.json();
      console.log(data);
      if (data.access_token && data.refresh_token) {
        // Update the database with new tokens
        await OAuthCredentials.updateOne({ _id: userId }, data);

        console.log("Tokens refreshed and updated in the database.");
      } else {
        console.error("Failed to refresh tokens. API response:", data);
      }
    } else {
      console.log("No need to refresh token yet.");
    }
  } catch (error) {
    console.error("Error refreshing token:", error);
  }
}

// Example: Call this function periodically to check token expiry
async function checkAndRefreshToken() {
  const userId = "677cd74aeab0f9937014e5e3"; // Replace with the actual user ID
  await refreshToken(userId);
}

// Schedule token refresh check every 30 minutes using node-cron
cron.schedule("*/30 * * * *", checkAndRefreshToken); // Runs every 30 minutes

// Define the file path
const filePath = path.join(__dirname, "server-reload-log.txt");

// Function to format the date in UTC
function formatUTCDate(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0"); // Months are 0-indexed
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  const seconds = String(date.getUTCSeconds()).padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

// Function to log server reload details
function logServerReload() {
  const timestamp = formatUTCDate(new Date());
  const logMessage = `Server reloaded at: ${timestamp}\n`;

  fs.appendFile(filePath, logMessage, (err) => {
    if (err) {
      console.error("Error writing to log file:", err);
    } else {
      console.log("Server reload details logged in UTC.");
    }
  });
}

// Log reload details when the server starts
logServerReload();

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
