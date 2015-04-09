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

var Promise = require('bluebird');
var request = Promise.promisifyAll(require('superagent'));
var jwku = Promise.promisifyAll(require('jwks-utils'));
var jws = require('jws');
var jwk2pem = require('pem-jwk').jwk2pem;

var TRUSTED_LIST_URI = 'http://oada.github.io/oada-trusted-lists/' +
        'client-registration.json';

// callback <= (err, trusted, payload)
module.exports = function(sig, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = undefined;
    }
    options = options || {};

    var decoded = Promise.try(function decode() {
        return jws.decode(sig);
    });

    var list = request
        .get(TRUSTED_LIST_URI)
        .timeout(options.timeout || 1000)
        .endAsync()
        .get('body');

    var trusted = Promise.join(decoded, list, function(decoded, list) {
        return list.indexOf(decoded.header.jku) !== -1;
    });

    var jwk = Promise.join(decoded, trusted, function(decoded, trusted) {
        var jku = decoded.header.jku;
        return jwku.jwkForSignatureAsync(sig, trusted && jku, options);
    });

    return Promise.join(decoded, trusted, jwk, function(decoded, trusted, jwk) {
        if (jws.verify(sig, 'RS256', jwk2pem(jwk))) {
            return [trusted, decoded.payload];
        } else {
            throw new Error('Invalid signature');
        }
    }).nodeify(callback, {spread: true});
};

module.exports.TRUSTED_LIST_URI = TRUSTED_LIST_URI;
