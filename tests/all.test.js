'use strict';

require('should');

const express = require('express');
const supertest = require('supertest');

const basicAuth = require('../lib');

const app = express();

//Requires basic auth with username 'Admin' and password 'secret1234'
const staticUserAuth = basicAuth({
    users: {
        'Admin': 'secret1234'
    },
    challenge: false
});

//Uses a custom (synchronous) authorizer function
const customAuthorizerAuth = basicAuth({
    authorizer: myAuthorizer
});

//Uses a custom (synchronous) authorizer function
const customCompareAuth = basicAuth({
    authorizer: myComparingAuthorizer
});

//Same, but sends a basic auth challenge header when authorization fails
const challengeAuth = basicAuth({
    authorizer: myAuthorizer,
    challenge: true
});

//Uses a custom asynchronous authorizer function
const asyncAuth = basicAuth({
    authorizer: myAsyncAuthorizer,
    authorizeAsync: true
});

const ctxAwareAuth = basicAuth({
    authorizer: myCtxAwareAuthorizer,
    passRequest: true
});

const ctxAwareAsyncAuth = basicAuth({
    authorizer: myCtxAwareAsyncAuthorizer,
    passRequest: true,
    authorizeAsync: true
});

const emptyCredentialsAuth = basicAuth({
    authorizer: emptyCredentialsAuthorizer,
    allowEmptyCredentials: true
});

//Uses a custom response body function
const customBodyAuth = basicAuth({
    users: { 'Foo': 'bar' },
    unauthorizedResponse: getUnauthorizedResponse
});

//Uses a static response body
const staticBodyAuth = basicAuth({
    unauthorizedResponse: 'Haaaaaha'
});

//Uses a JSON response body
const jsonBodyAuth = basicAuth({
    unauthorizedResponse: { foo: 'bar' }
});

//Uses a custom realm
const realmAuth = basicAuth({
    challenge: true,
    realm: 'test'
});

//Uses a custom realm function
const realmFunctionAuth = basicAuth({
    challenge: true,
    realm: function () {
        return 'bla';
    }
});

function ok_response (req, res) {
    res.status(200).send('You passed');
}

app.get('/static', staticUserAuth, ok_response);
app.get('/custom', customAuthorizerAuth, ok_response);
app.get('/custom-compare', customCompareAuth, ok_response);
app.get('/challenge', challengeAuth, ok_response);
app.get('/async', asyncAuth, ok_response);
app.get('/ctx-aware/:ctx_param', ctxAwareAuth, ok_response);
app.get('/ctx-aware-async/:ctx_param', ctxAwareAsyncAuth, ok_response);
app.get('/empty-credentials', emptyCredentialsAuth, ok_response);
app.get('/custombody', customBodyAuth, ok_response);
app.get('/staticbody', staticBodyAuth, ok_response);
app.get('/jsonbody', jsonBodyAuth, ok_response);
app.get('/realm', realmAuth, ok_response);
app.get('/realmfunction', realmFunctionAuth, ok_response);

//Custom authorizer checking if the username starts with 'A' and the password with 'secret'
function myAuthorizer(username, password) {
    return username.startsWith('A') && password.startsWith('secret');
}

//Same but asynchronous
function myAsyncAuthorizer(username, password, cb) {
    return cb(null, myAuthorizer(username, password));
}

function myCtxAwareAuthorizer(req, username, password) {
    return (
        myAuthorizer(username, password)
        && username === req.params['ctx_param']
    );
}

function myCtxAwareAsyncAuthorizer(req, username, password, cb) {
    return cb(null, myCtxAwareAuthorizer(req, username, password));
}

function emptyCredentialsAuthorizer(username, password) {
    return username === null && password === null;
}

function myComparingAuthorizer(username, password) {
    return (
        basicAuth.safeCompare(username, 'Testeroni') &
        basicAuth.safeCompare(password, 'testsecret')
    );
}

function getUnauthorizedResponse(req) {
    return req.auth
        ? ('Credentials ' + req.auth.user + ':' + req.auth.password + ' rejected')
        : 'No credentials provided';
}

describe('express-basic-auth', function() {
    describe('safe compare', function() {
        const safeCompare = basicAuth.safeCompare;

        it('should return false on different inputs', function() {
            (!!safeCompare('asdf', 'rftghe')).should.be.false();
        });

        it('should return false on prefix inputs', function() {
            (!!safeCompare('some', 'something')).should.be.false();
        });

        it('should return false on different inputs', function() {
            (!!safeCompare('anothersecret', 'anothersecret')).should.be.true();
        });
    });

    describe('static users', function() {
        const endpoint = '/static';

        it('should reject on missing header', function(done) {
            supertest(app)
                .get(endpoint)
                .expect(401, done);
        });

        it('should reject on wrong credentials', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('dude', 'stuff')
                .expect(401, done);
        });

        it('should reject on shorter prefix', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('Admin', 'secret')
                .expect(401, done);
        });

        it('should reject without challenge', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('dude', 'stuff')
                .expect(function (res) {
                    if(res.headers['WWW-Authenticate'])
                        throw new Error('Response should not have a challenge');
                })
                .expect(401, done);
        });

        it('should accept correct credentials', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('Admin', 'secret1234')
                .expect(200, 'You passed', done);
        });
    });

    describe('custom authorizer', function() {
        const endpoint = '/custom';

        it('should reject on missing header', function(done) {
            supertest(app)
                .get(endpoint)
                .expect(401, done);
        });

        it('should reject on wrong credentials', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('dude', 'stuff')
                .expect(401, done);
        });

        it('should accept fitting credentials', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('Aloha', 'secretverymuch')
                .expect(200, 'You passed', done);
        });

        describe('with safe compare', function() {
            const endpoint = '/custom-compare';

            it('should reject wrong credentials', function(done) {
                supertest(app)
                    .get(endpoint)
                    .auth('bla', 'blub')
                    .expect(401, done);
            });

            it('should reject prefix credentials', function(done) {
                supertest(app)
                    .get(endpoint)
                    .auth('Test', 'test')
                    .expect(401, done);
            });

            it('should accept fitting credentials', function(done) {
                supertest(app)
                    .get(endpoint)
                    .auth('Testeroni', 'testsecret')
                    .expect(200, 'You passed', done);
            });
        });
    });

    describe('async authorizer', function() {
        const endpoint = '/async';

        it('should reject on missing header', function(done) {
            supertest(app)
                .get(endpoint)
                .expect(401, done);
        });

        it('should reject on wrong credentials', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('dude', 'stuff')
                .expect(401, done);
        });

        it('should accept fitting credentials', function(done) {
            supertest(app)
                .get(endpoint)
                .auth('Aererer', 'secretiveStuff')
                .expect(200, 'You passed', done);
        });
    });

    describe('context aware authorizer', function () {
        it('should reject on missing header', function(done) {
            supertest(app)
                .get('/ctx-aware/Admin')
                .expect(401, done);
        });

        it('should reject on wrong credentials', function(done) {
            supertest(app)
                .get('/ctx-aware/Admin')
                .auth('dude', 'stuff')
                .expect(401, done);
        });

        it('should reject based on context', function(done) {
            // Check the '/ctx-aware' route to see how context is captured, and
            // myCtxAwareAuthorizer to see how context is processed.
            supertest(app)
                .get('/ctx-aware/Root')
                .auth('Admin', 'secretiveStuff')
                .expect(401, done);
        });

        it('should accept fitting credentials', function(done) {
            // Check the '/ctx-aware' route to see how context is captured, and
            // myCtxAwareAuthorizer to see how context is processed.
            supertest(app)
                .get('/ctx-aware/Admin')
                .auth('Admin', 'secretiveStuff')
                .expect(200, 'You passed', done);
        });
    });

    describe('context aware async authorizer', function () {
        it('should reject on missing header', function(done) {
            supertest(app)
                .get('/ctx-aware-async/Admin')
                .expect(401, done);
        });

        it('should reject on wrong credentials', function(done) {
            supertest(app)
                .get('/ctx-aware-async/Admin')
                .auth('dude', 'stuff')
                .expect(401, done);
        });

        it('should reject based on context', function(done) {
            // Check the '/ctx-aware' route to see how context is captured, and
            // myCtxAwareAuthorizer to see how context is processed.
            supertest(app)
                .get('/ctx-aware-async/Root')
                .auth('Admin', 'secretiveStuff')
                .expect(401, done);
        });

        it('should accept fitting credentials', function(done) {
            // Check the '/ctx-aware' route to see how context is captured, and
            // myCtxAwareAuthorizer to see how context is processed.
            supertest(app)
                .get('/ctx-aware-async/Admin')
                .auth('Admin', 'secretiveStuff')
                .expect(200, 'You passed', done);
        });
    });

    describe('empty credentials authorizer', function () {
        it('should accept requests without credentials', function (done) {
            supertest(app)
                .get('/empty-credentials')
                .expect(200, 'You passed', done);
        });
    });

    describe('custom response body', function() {
        it('should reject on missing header and generate resposne message', function(done) {
            supertest(app)
                .get('/custombody')
                .expect(401, 'No credentials provided', done);
        });

        it('should reject on wrong credentials and generate response message', function(done) {
            supertest(app)
                .get('/custombody')
                .auth('dude', 'stuff')
                .expect(401, 'Credentials dude:stuff rejected', done);
        });

        it('should accept fitting credentials', function(done) {
            supertest(app)
                .get('/custombody')
                .auth('Foo', 'bar')
                .expect(200, 'You passed', done);
        });

        it('should reject and send static custom resposne message', function(done) {
            supertest(app)
                .get('/staticbody')
                .expect(401, 'Haaaaaha', done);
        });

        it('should reject and send static custom json resposne message', function(done) {
            supertest(app)
                .get('/jsonbody')
                .expect(401, { foo: 'bar' }, done);
        });
    });

    describe('challenge', function() {
        it('should reject with blank challenge', function(done) {
            supertest(app)
                .get('/challenge')
                .expect('WWW-Authenticate', 'Basic')
                .expect(401, done);
        });

        it('should reject with custom realm challenge', function(done) {
            supertest(app)
                .get('/realm')
                .expect('WWW-Authenticate', 'Basic realm="test"')
                .expect(401, done);
        });

        it('should reject with custom generated realm challenge', function(done) {
            supertest(app)
                .get('/realmfunction')
                .expect('WWW-Authenticate', 'Basic realm="bla"')
                .expect(401, done);
        });
    });
});
