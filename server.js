const express = require("express");
const crypto = require("crypto-js");
const dotenv = require("dotenv");
const logger = require("morgan");
const cors = require("cors");
const qs = require("querystring");
const axios = require("axios");

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

/// OAuth callback endpoint
app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  console.log(code);
  if (!code) {
    console.error("OAuth Authorization Code is missing.");
    return res.status(400).send("No OAuth Authorization Code received.");
  }

  try {
    // Exchange the OAuth code for an access token
    const credentials = await getAccessToken(code);
    console.log(credentials);
    // Debugging: Log credentials to ensure proper access token retrieval
    console.debug("OAuth Token Credentials:", credentials);

    // Set the access token in a secure cookie for frontend access
    res.cookie("accessToken", credentials.access_token, {
      httpOnly: true, // Makes cookie accessible only via HTTP requests, not JS (security measure)
      secure: true, // Ensures cookie is sent only over HTTPS
      domain: ".clingy.app", // Shared domain, if both frontend and backend are on subdomains of this domain
      path: "/", // Path where the cookie is available
      maxAge: 3600000, // 1 hour expiry
      sameSite: "None",
    });

    // Redirect to the thank-you page
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
  console.log("----------------------------------------");
  console.log(process.env.GHL_CLIENT_ID);
  console.log(process.env.GHL_CLIENT_SECRET);
  console.log(code);
  console.log("----------------------------------------");
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
    console.log("--_____---__---____---___-------------------------");
    console.log(response);
    console.log("--_____---__---____---___-------------------------");

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

// Function to make authenticated API requests
async function apiRequest(method, endpoint, credentials, data = {}) {
  try {
    const response = await axios({
      method,
      url: `${process.env.GHL_API_DOMAIN}${endpoint}`,
      headers: {
        Authorization: `Bearer ${credentials.access_token}`,
        "Content-Type": "application/json",
      },
      data,
    });

    return response.data;
  } catch (error) {
    console.error("API request failed:", error);
    // throw new Error(`API request failed: ${error.message}`);
  }
}

// Function to refresh the access token
async function refreshAccessToken(credentials) {
  const body = qs.stringify({
    client_id: process.env.GHL_CLIENT_ID,
    client_secret: process.env.GHL_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: credentials.refresh_token,
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
