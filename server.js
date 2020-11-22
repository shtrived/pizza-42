const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const app = express();

const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const authConfig = require("./auth_config.json");

const jsonwebtoken = require("jsonwebtoken");
const axios = require("axios").default;

// For accessing API Management APIs
const config = require('./auth_config.json');
const client_id = config.mgmt_clientId || process.env.mgmt_clientId;
const client_secret = config.mgmt_clientSecret || process.env.mgmt_clientSecret;
const domain = config.domain || process.env.domain;
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
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithms: ["RS256"]
});


app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});


app.post("/place_order", checkJwt, async (req, res) => {
  const authorization_header = (req && req.headers && req.headers.authorization) ? req.headers.authorization : null;
  const token = authorization_header.startsWith('Bearer ') ? authorization_header.split('Bearer ')[1] : authorization_header;

  // Check for the scope in the token
  const currentToken = jsonwebtoken.decode(token, { complete: true });
  if (currentToken.payload.scope && (currentToken.payload.scope.indexOf('write:order') === -1)) {
    res.send({
      status: "Client does not have right permissions to place order!"
    });
  }

  const user = req.body ? req.body.user : {};

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
  const requestUrl = `https://1701ncc.auth0.com/api/v2/users/${user.sub}`;
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
    .patch(requestUrl, body,{
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
