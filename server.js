const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const app = express();

const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const authConfig = require("./auth_config.json");

const jsonwebtoken = require("jsonwebtoken");

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

app.post("/place_order", checkJwt, (req, res) => {
  const authorization_header = (req && req.headers && req.headers.authorization) ? req.headers.authorization : null;
  const token = authorization_header.startsWith('Bearer ') ? authorization_header.split('Bearer ')[1] : authorization_header;

  // Check for the scope in the token
  const currentToken = jsonwebtoken.decode(token, { complete: true });
  if (currentToken.payload.scope && (currentToken.payload.scope.indexOf('write:order') > -1)) {
    res.send({
      status: "Your order for pizza has been successfully placed!",
      order: req.body
    });
  } else {
    res.send({
      status: "Client does not have right permissions to place order!"
    });
  }

});

app.get("/order_history", checkJwt, (req, res) => {
  const authorization_header = (req && req.headers && req.headers.authorization) ? req.headers.authorization : null;
  const token = authorization_header.startsWith('Bearer ') ? authorization_header.split('Bearer ')[1] : authorization_header;

  const currentToken = jsonwebtoken.decode(token, { complete: true });
  if (currentToken.payload.scope && (currentToken.payload.scope.indexOf('write:order') > -1)) {
    res.send({
      msg: "Your order for pizza #" + Math.floor((Math.random() * (43)) + 1) + " has been successfully placed!"
    });
  } else {
    res.send({
      msg: "Client does not have right permissions to place order!"
    });
  }

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
