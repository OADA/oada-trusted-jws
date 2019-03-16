/* Copyright 2019 Open Ag Data Alliance
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

const Promise = require('bluebird');
const request = Promise.promisifyAll(require('superagent'));
const jwku = Promise.promisifyAll(require('jwks-utils'));
const jws = require('jws');
const jwt = require('jsonwebtoken');
const jwk2pem = require('pem-jwk').jwk2pem;
const warn  = require('debug')('oada-trusted-jws:warn');
const info  = require('debug')('oada-trusted-jws:info');
const trace = require('debug')('oada-trusted-jws:trace');

var TRUSTED_LIST_URI = 'https://oada.github.io/oada-trusted-lists/client-registration.json';

// callback <= (err, trusted, payload)
// options: {
//   timeout: 1000, // ms
//   trustedListCacheTime: 3600, // seconds
//   additionalTrustedListURIs: [ 'https://somewhere.com/client-registration.json' ],
// }

const trustedListCache = {};
module.exports = function(sig, options, callback) {
  return Promise.try(() => {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    options = options || {};
    // Since 0 is a valid timeout, have to check whether it's actually a number instead of just truthy
    options.timeout = typeof options.timeout === 'number' ? options.timeout : 1000;
    // Default trusted list cached for one hour, in seconds
    options.trustedListCacheTime = typeof options.trustedListCacheTime === 'number' ? options.trustedListCacheTime : 3600; // seconds
    options.additionalTrustedListURIs = options.additionalTrustedListURIs || [];

    // Build the list of all the trusted lists we're going to check
    let trustedListURIs = [ TRUSTED_LIST_URI ].concat(options.additionalTrustedListURIs);
    trace('Using trustedListURIs = ', trustedListURIs);

    //---------------------------------------------------------------------------
    // Loop over all the trusted list URI's, checking if we already have in cache
    // If in cache, also check that they are not stale and need to be replaced
    const now = Date.now() / 60;
    return Promise.map(trustedListURIs, listURI => {
      if (  !trustedListCache[listURI] 
          || trustedListCache[listURI].timeLastFetched < (now - options.trustedListCacheTime)) { // either not cached, or cache is old
        trace('listURI ',listURI,' is not in cache or is stale, fetching...');
        return request.get(listURI)
         .timeout(options.timeout)
         .then(result => {
           const newCacheObj = {
             timeLastFetched: now,
             body: result.body,
             listURI,
           };
           trustedListCache[listURI] = newCacheObj;
           trace('Fetched list from URI ',listURI, ', putting this into the cache: ', newCacheObj);
           return newCacheObj;
         }).catch(err => {
           warn('WARNING: unable to fetch trusted list at URI.',listURI);
           return false;
         });
      }
      // else, we have it in the cache, so return the cached body directly
      trace('listURI ', listURI, ' is in cache, returning cached value: ', trustedListCache[listURI]);
      return Promise.resolve(trustedListCache[listURI]);
    });

  //-----------------------------------------------------------------------------
  // Now, look through all the lists to see if the jku on the signature is in any of the trusted lists
  }).then(lists => {
    // jws.decode throws if the signature is invalid
    var decoded = jws.decode(sig);
    trace('Decoded the signature, decoded = ', decoded);

    if (!decoded || !decoded.header) {
      trace('decoded signature is null or has no header.');
      return { decoded: false, trusted: false, jwk: false };
    }
    const foundList = lists.find(l => {
      if (!l || !l.body) return false;
      if (typeof l.body.find !== 'function') return false; // not an array
      return l.body.find(i => (i === decoded.header.jku));
    });
    if (!foundList) {
      trace('header of decoded signature does not have a jku key that '
          +'exists in any of the trusted lists. decoded.header = ', decoded.header);
    }

    // Otherwise, we need to go ahead and figure out the jwk.  If we found the jku from
    // the header in a trusted list, then the call below will tell jwkForSignatureAsync to 
    // use that jku, go there and get the list of keys, then use the kid to lookup the jwk.
    // If it was not found in a trusted list, then jwkForSignatureAsync will just return either
    // the jwk from the header directly or the corresponding jwk from a jku lookup
    return Promise.props({ 
      decoded,
      trusted: !!foundList,  // true/false whether trusted/not_trusted
      jwk: jwku.jwkForSignatureAsync(sig, foundList ? decoded.header.jku : false, { timeout: options.timeout }),
    });

  // Now we can go ahead and verify the signature with the jwk:
  }).then(({ decoded, trusted, jwk }) => {
    return [ trusted, jwt.verify(sig, jwk2pem(jwk)) ];

  // And signal the callback with any thrown errors, or (trusted, clientRegistration) if no errors
  }).nodeify(callback, { spread: true });

};

module.exports.TRUSTED_LIST_URI = TRUSTED_LIST_URI;
