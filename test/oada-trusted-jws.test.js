/* Copyright 2015 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var chai = require('chai');
var chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
var Promise = require('bluebird');
var expect = chai.expect;
var nock = require('nock');
var url = require('url');
var jws = require('jws');
var jwk2pem = require('pem-jwk').jwk2pem;

// Good enough?
Promise.longStackTraces();
chai.config.includeStack = true;
chaiAsPromised.transferPromiseness = function(assertion, promise) {
    var p = promise.error(function(e) {
        throw e.cause;
    });
    assertion.then = promise.then.bind(p);
};

var check = require('../');

var TEST_ROOT = 'https://test.example.org/';

var privJwk = require('./private.jwk.json');
var pubJwk = {};
['kid', 'n', 'e', 'kty'].forEach(function(pubKey) {
    pubJwk[pubKey] = privJwk[pubKey];
});

describe('oada-trusted-jws', function() {
    var sig;
    var payload = 'DEAD BEEF';

    beforeEach(function mockList() {
        var uri = url.parse(check.TRUSTED_LIST_URI);
        nock(url.format({protocol: uri.protocol, host:uri.host}))
            .get(uri.path)
            .reply(200, [TEST_ROOT + 'trusted']);
    });

    beforeEach(function mockJKU() {
        nock(TEST_ROOT)
            .filteringPath(function() { return '/'; })
            .get('/')
            .reply(200, {keys: [pubJwk]});
    });

    it('should error for invalid signature', function() {
        sig = jws.sign({
            header: {
                kid: privJwk.kid,
                jku: TEST_ROOT,
                alg: 'HS256'
            },
            payload: payload,
            secret: 'FOO'
        });

        return expect(check(sig))
            .to.eventually.be.rejectedWith('Invalid signature');
    });

    ['trusted', 'untrusted'].forEach(function(trust) {
        describe('for ' + trust + ' signature', function() {
            var trusted = trust === 'trusted';

            before(function genSig() {
                sig = jws.sign({
                    header: {
                        kid: privJwk.kid,
                        jku: TEST_ROOT + trust,
                        alg: 'RS256'
                    },
                    payload: payload,
                    secret: jwk2pem(privJwk)
                });
            });

            it('should return trusted ' + trusted, function() {
                return expect(check(sig).get(0)).to.eventually.equal(trusted);
            });

            it('should return the signature payload', function() {
                return expect(check(sig).get(1))
                    .to.eventually.deep.equal(payload);
            });
        });
    });

    it('should work with callback', function(done) {
        check({}, function() {
            done();
        });
    });
});
