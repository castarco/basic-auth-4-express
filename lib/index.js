'use strict';

const auth = require('basic-auth');
const assert = require('assert');
const timingSafeEqual = require('crypto').timingSafeEqual;

// Credits for the actual algorithm go to github/@Bruce17
// Thanks to github/@hraban for making me implement this
function safeCompare(userInput, secret) {
    const userInputLength = Buffer.byteLength(userInput);
    const secretLength = Buffer.byteLength(secret);

    const userInputBuffer = Buffer.alloc(userInputLength, 0, 'utf8');
    userInputBuffer.write(userInput);
    const secretBuffer = Buffer.alloc(userInputLength, 0, 'utf8');
    secretBuffer.write(secret);

    return !!(timingSafeEqual(userInputBuffer, secretBuffer) & userInputLength === secretLength);
}

function ensureFunction(option, defaultValue) {
    if (option === undefined) {
        return () => defaultValue;
    }

    if (typeof option !== 'function') {
        return () => option;
    }

    return option;
}

function buildMiddleware(options) {
    const challenge = !!options.challenge;
    const users = options.users || {};
    const authorizer = options.authorizer || staticUsersAuthorizer;
    const isAsync = !!options.authorizeAsync;
    const passRequest = !!options.passRequest;
    const allowEmptyCredentials = !!options.allowEmptyCredentials;
    const getResponseBody = ensureFunction(options.unauthorizedResponse, '');
    const realm = ensureFunction(options.realm);

    assert(typeof users === 'object', `Expected an object for the basic auth users, found ${typeof users} instead`);
    assert(typeof authorizer === 'function', `Expected a function for the basic auth authorizer, found ${typeof authorizer} instead`);

    function staticUsersAuthorizer(username, password) {
        let authorized = false;
        for (const i in users) {
            authorized |= safeCompare(username, i) & safeCompare(password, users[i]);
        }
        return authorized;
    }

    return function authMiddleware(req, res, next) {
        const authentication = auth(req);
        const {name, pass} = authentication
            ? authentication
            : {name: null, pass: null};

        if (!authentication && !allowEmptyCredentials) {
            return unauthorized();
        }
        req.auth = {user: name, password: pass};

        if (isAsync) {
            return passRequest
                ? authorizer(req, name, pass, authorizerCallback)
                : authorizer(name, pass, authorizerCallback);
        }
        if (passRequest) {
            if (!authorizer(req, name, pass)) {
                return unauthorized();
            }
        } else {
            if (!authorizer(name, pass)) {
                return unauthorized();
            }
        }
        return next();

        function unauthorized () {
            if (challenge) {
                const realmName = realm(req);
                const challengeString = (realmName)
                    ? `Basic realm="${realmName}"`
                    : 'Basic';

                res.set('WWW-Authenticate', challengeString);
            }

            //TODO: Allow response body to be JSON (maybe autodetect?)
            const response = getResponseBody(req);

            if (typeof response === 'string') {
                return res.status(401).send(response);
            }

            return res.status(401).json(response);
        }

        function authorizerCallback(err, approved) {
            assert.ifError(err);

            if (approved) {
                return next();
            }

            return unauthorized();
        }
    };
}

buildMiddleware.safeCompare = safeCompare;
module.exports = buildMiddleware;
