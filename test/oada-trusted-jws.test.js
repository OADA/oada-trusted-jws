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
  beforeEach(function mockList() {
    const uri = url.parse(check.TRUSTED_LIST_URI);
    nock(url.format({protocol: uri.protocol, host:uri.host}))
    .get(uri.path)
    .reply(200, [TEST_ROOT + 'trusted']);
  });

  // Setup the mock server to serve it's jwk set at the URL given in the mocked list above
  beforeEach(function mockJWKS() {
    nock(TEST_ROOT)
    .filteringPath(function() { return '/'; })
    .get('/')
    .reply(200, {keys: [pubJwk]});
  });

  it('should work with callback', function(done) {
    check({}, () => done());
  });

  it('should error for invalid signature', function() {
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
          jku: TEST_ROOT + 'trusted'
        },
      });
      return expect(check(sig).get(0)).to.eventually.equal(true);
    });

    it('should return the signature payload', function() {
      const sig = jwt.sign(payload, jwk2pem(privJwk), {
        algorithm: 'RS256',
        header: {
          kid: privJwk.kid,
          jku: TEST_ROOT + 'trusted'
        },
      });
      return expect(check(sig).get(1)).to.eventually.deep.equal(payload);
    });
  });

});
