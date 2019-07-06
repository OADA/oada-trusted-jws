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

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
const Promise = require('bluebird');
const expect = chai.expect;
const nock = require('nock');
const url = require('url');
const jwt = require('jsonwebtoken');
const jwk2pem = require('pem-jwk').jwk2pem;
const debug = require('debug');
const log = debug('oada-trusted-jws:test:trace');

// The module to be "checked" (i.e. under test)
const check = require('../');

// We will mock a server for the tests that use this URL:
const TEST_ROOT = 'https://test.example.org/';

// keypair used for signing in the tests:
const privJwk = require('./private.jwk.json');
// A  public key is same as private key, but only keeping kid, n, e, and kty
const pubJwk = {
  kid: privJwk.kid,
    n: privJwk.n,
    e: privJwk.e,
  kty: privJwk.kty,
};


describe('oada-trusted-jws', function() {
  const payload = 'DEAD BEEF';

  // Setup the mock server to serve a trusted list with a URL for it's own jwk set 
  // When the main function tries to get the Trusted List, this will respond instead of github:
  beforeEach(function mockList() {
    const uri = url.parse(check.TRUSTED_LIST_URI);
    nock(url.format({protocol: uri.protocol, host:uri.host}))
    .log(log)
    .get(uri.path)
    .reply(200, { version: "2", jkus: [ TEST_ROOT ], jwks: { keys: [] } });
    // this is what version 1 trusted list looked like: .reply(200, [TEST_ROOT]);
  });

  // Setup the mock server to serve it's jwk set at the URL given in the mocked list above
  beforeEach(function mockJWKS() {

    // Setup the correct "trusted" one that's in mocked trusted list above:
    nock(TEST_ROOT)
    .log(log)
    //.filteringPath(function() { return '/'; })

    // For the root, it's in the trusted list:
    .get('/')
    .reply(200, {keys: [pubJwk]})

    // Also, host this one as the same list, but not considered trusted
    .get('/untrusted')
    .reply(200, { keys: [ pubJwk ] });
  });

  it('should error (throw) for invalid signature', function() {
    // create a signature with private key = "FOO"
    const sig = jwt.sign(payload, 'FOO', {
      algorithm: 'HS256',
      header: {
        kid: privJwk.kid,
        jku: TEST_ROOT
      }
    });
    return expect(check(sig)).to.eventually.be.rejected;
  });

  //--------------------------------------------------------------------
  describe('for valid but untrusted signature', function() {
    it('should return false for "trusted" return value', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT + 'untrusted',
        },
      });
      return expect(check(sig).get(0)).to.eventually.equal(false);
    });

    it('should return the signature payload even though untrusted', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT + 'untrusted',
        },
      });
      return expect(check(sig).get(1)).to.eventually.deep.equal(payload);
    });
  });

  //--------------------------------------------------------------------
  describe('for valid trusted signature', function() {
    it('should return true for "trusted" return value', () => {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT,
        },
      });
      return expect(check(sig).get(0)).to.eventually.equal(true);
    });

    it('should return the signature payload', function() {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT,
        },
      });
      return expect(check(sig).get(1)).to.eventually.deep.equal(payload);
    });
  });

});
