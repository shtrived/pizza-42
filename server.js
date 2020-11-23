const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const app = express();

const jwt = require("express-jwt");
const jwtAuthz = require('express-jwt-authz');
const jwksRsa = require("jwks-rsa");
const authConfig = require("./auth_config.json");

const jsonwebtoken = require("jsonwebtoken");
const axios = require("axios").default;

// For accessing API Management APIs
const client_id = authConfig.mgmt_clientId || process.env.mgmt_clientId;
const client_secret = authConfig.mgmt_clientSecret || process.env.mgmt_clientSecret;
const domain = authConfig.domain || process.env.domain;
const app_audience = authConfig.audience || process.env.audience;

const url = `https://${domain}/oauth/token`;


app.use(morgan("dev"));
app.use(helmet());
app.use(express.static(join(__dirname, "public")));
app.use(express.json({ limit: '1mb' }));

// create the JWT middleware
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${domain}/.well-known/jwks.json`
  }),

  audience: app_audience,
  issuer: `https://${domain}/`,
  scope: 'write:order',
  algorithms: ["RS256"]
});


app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});


app.post("/place_order/:id", checkJwt, jwtAuthz([ 'write:order' ], {} ), async (req, res) => {

  try {
    const user = req.params ? req.params.id : null;
    if (!user) {
      throw new Error('No valid user id passed');
    }

    // Create randomized order detail
    const today = new Date(Date.now());
    const order = {
      order_date: today.toString(),
      order_item: `Pizza #${Math.floor((Math.random() * (43)) + 1)}`
    }

    const response = await axios
      .post(url, {
        client_id: client_id,
        client_secret: client_secret,
        grant_type: "client_credentials",
        audience: `https://${domain}/api/v2/`
      });

    const data = response.data;
    const access_token = data.access_token;

    // Now get the complete user profile to get current list of order history
    const requestUrl = `https://1701ncc.auth0.com/api/v2/users/${user}`;
    const userProfile = await axios
      .get(requestUrl, {
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${access_token}`
        }
      });

    const profile = await userProfile.data;
    const metadata = profile.user_metadata ? profile.user_metadata : {};
    const history = metadata.history || [];
    history.push(order);

    const body = {
      user_metadata: {
        history: history
      }
    }

    const updatedProfile = await axios
      .patch(requestUrl, body, {
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${access_token}`
        }
      });

    const result = updatedProfile.data;
    res.send({
      status: "Your order for pizza has been successfully placed!",
      order: order
    });
  } catch (err) {
    console.log(`Error while placing order ... ${err}`);
    throw err;
  }

});

app.get("/order_history/:id", checkJwt, async (req, res) => {

  // Get access token for fetching user profile
  const user = req.body ? req.body.user : {};
  const response = await axios
    .post(url, {
      client_id: client_id,
      client_secret: client_secret,
      grant_type: "client_credentials",
      audience: `https://${domain}/api/v2/`
    });

  const data = response.data;
  const access_token = data.access_token;

  const params = req.params;

  // Now get the complete user profile to get current list of order history
  const requestUrl = `https://1701ncc.auth0.com/api/v2/users/${params.id}`;
  const userProfile = await axios
    .get(requestUrl, {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${access_token}`
      }
    });

  // Return the history
  const profile = await userProfile.data;
  const metadata = profile.user_metadata ? profile.user_metadata : {};
  const history = metadata.history || [];

  res.send(history);
});

app.get("/auth_config.json", (req, res) => {
  res.sendFile(join(__dirname, "auth_config.json"));
});

app.get("/config", (req, res) => {
  res.sendFile(join(__dirname, "auth_config.json"));
});

app.get("/*", (_, res) => {
  res.sendFile(join(__dirname, "index.html"));
});

// Error Handler
app.use(function(err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    return res.status(401).send({ msg: "Invalid token" });
  }

  next(err, req, res);
});


// process.on("SIGINT", function() {
//   process.exit();
// });

module.exports = app;
