
const express = require('express');

const router = express.Router();
const session = require('express-session');
const bodyParser = require('body-parser');
const log4js = require('log4js');

const logger = log4js.getLogger();
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const request = require('request').defaults({ rejectUnauthorized: false });
const configjs = require('./lib/config/init-auth-config.js');
const inspectClient = require('./lib/inspect-client');

const log4jsConfig = process.env.LOG4JS_CONFIG ? JSON.parse(process.env.LOG4JS_CONFIG) : undefined;
log4js.configure(log4jsConfig || './config/log4js.json');


const app = (req, res, next) => {
  let token;
  if (req.headers.authorization || req.headers.Authorization) {
    token = req.headers.authorization ? req.headers.authorization : req.headers.Authorization;
    const words = token.trim().split(/[\s,]+/);
    if (!(words[0].toLowerCase().match('bearer'))) {
      return res.status(403).send('No bearer in value');
    }
    if (words[1] && words[1].length > 1) {
      [, token] = words;
    }
  } else if (req.get('Authorization')) {
    token = req.get('Authorization');
  }

  if (!token) {
    return res.status(401).send('The request is unauthorized, no token provided.');
  }

  inspectClient.inspect(req, token, (err, response, body) => {
    if (err) {
      return res.status(500).send(err.details);
    } if (body && body.status && body.status.error) {
      return res.status(401).send(body.status.error);
    } if (body && body.status && body.status.user) {
      req.user = body.status.user;
      req.token = token;
      logger.info(req.user);
      return next();
    }
    return res.status(401).send('The token provided is not valid');
  });
  return null;
};

const ui = () => {
  let contextpath = '';

  router.get('*', (req, res, next) => {
    contextpath = req.baseUrl;
    next();
  });

  if (process.env.NODE_ENV === 'production') {
    router.all('*', app);
  } else {
    configjs.initialize((err, config) => {
      if (err) {
        logger.error('Initilized failed', err);
        process.exit(1);
      }
      // token review api to validate Bearer token/ retrieve user info

      const options = {
        url: `${config.ocp.apiserver_url}/apis/authentication.k8s.io/v1/tokenreviews`,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${config.ocp.serviceaccount_token}`,
        },
        json: true,
        body: {
          apiVersion: 'authentication.k8s.io/v1',
          kind: 'TokenReview',
          spec: {
            token: config.ocp.serviceaccount_token,
          },
        },
      };

      const callbackUrl = `${config.ocp.oauth2_redirecturl}`;

      passport.use(new OAuth2Strategy({
        // state: true,
        authorizationURL: `${config.ocp.oauth2_authorizepath}`,
        tokenURL: `${config.ocp.oauth2_tokenpath}`,
        clientID: config.ocp.oauth2_clientid,
        clientSecret: config.ocp.oauth2_clientsecret,
        callbackURL: callbackUrl,
        scope: 'user:full',
        passReqToCallback: true,
      },
      async (req, accessToken, refreshToken, profile, cb) => {
        options.body.spec.token = accessToken;

        // retrieving user info through token review api
        request.post(options, (err1, resp2, reviewbody) => {
          if (err1) {
            return cb(err1);
          }
          if (reviewbody.status && reviewbody.status.user) {
            // eslint-disable-next-line no-param-reassign
            reviewbody.status.user.token = accessToken;
            return cb(null, reviewbody.status.user);
          }
          return cb(new Error('Server Error'));
        });
      }));

      passport.serializeUser((user, done) => {
        done(null, user);
      });

      passport.deserializeUser((user, done) => {
        done(null, user);
      });
    });

    router.use(session(
      { secret: process.env.OAUTH2_CLIENT_SECRET, resave: true, saveUninitialized: true },
    ));
    router.use(bodyParser.urlencoded({ extended: false }));
    router.use(passport.initialize());
    router.use(passport.session());

    router.get(`${contextpath}/auth/login`, passport.authenticate('oauth2'));

    router.get(`${contextpath}/auth/callback`, passport.authenticate('oauth2', { failureRedirect: `${contextpath}/auth/login` }), (req, res) => {
      // logger.info(req.headers);
      res.cookie('acm-access-token-cookie', req.session.passport.user.token);
      req.user = req.session.passport.user;
      const redirectURL = req.cookies.redirectURL === '' ? `${contextpath}/welcome` : req.cookies.redirectURL;
      res.clearCookie('redirectURL');
      res.redirect(redirectURL);
    });

    router.get(`${contextpath}/logout`, (req, res) => {
      req.session.destroy((err) => {
        if (err) {
          return logger.error(err);
        }
        res.clearCookie('connect.sid');
        return res.redirect(`${contextpath}/auth/login`);
      });
    });

    router.all('*', (req, res, next) => {
      // logger.info(req.headers);
      if (!req.headers['x-forwarded-access-token'] && (!req.session.passport || !req.session.passport.user) && !req.cookies['acm-access-token-cookie']) {
        res.cookie('redirectURL', req.originalUrl);
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
        res.redirect(`${contextpath}/auth/login`);
      } else {
        // header exists, set it on cookie if doesn't exist
        if (!req.cookies['acm-access-token-cookie'] && req.headers['x-forwarded-access-token']) {
          res.cookie('acm-access-token-cookie', req.headers['x-forwarded-access-token']);
        }
        // cookie exists, need to validate before proceeding
        const token = req.headers['x-forwarded-access-token'] || req.cookies['acm-access-token-cookie'] || req.session.passport.user.token;
        logger.info('Already logged in: ', token);
        inspectClient.inspect(req, token, (err, response, body) => {
          if (err) {
            return res.status(500).send(err.details);
          } if (body && body.status && body.status.user && response.statusCode === 201) {
            req.user = body.status.user;
            logger.info(req.user);
            logger.info('Security middleware check passed');
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = 1;
            return next();
          }
          logger.info('Security middleware check failed; redirecting to login');
          return res.redirect(`${contextpath}/auth/login`);
        });
      }
    });
  }


  return router;
};


module.exports.app = app;
module.exports.ui = ui;
