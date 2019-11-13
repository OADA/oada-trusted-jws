[![Build Status](https://travis-ci.org/OADA/oada-trusted-jws-js.svg?branch=master)](https://travis-ci.org/OADA/oada-trusted-jws-js)
[![Coverage Status](https://coveralls.io/repos/OADA/oada-trusted-jws-js/badge.svg?branch=master)](https://coveralls.io/r/OADA/oada-trusted-jws-js?branch=master)
[![Dependency Status](https://david-dm.org/oada/oada-trusted-jws-js.svg)](https://david-dm.org/oada/oada-trusted-jws-js)
[![License](http://img.shields.io/:license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

# oada-trusted-jws #

THIS LIBRARY IS DEPRECATED.  WE USE OADA-CERTS NOW INSTEAD.

## Installation ##
```shell
npm install oada-trusted-jws
```

## Usage ##
```javascript
var check = require('oada-trusted-jws');

var signature = /* Get there from somewhere like jwt.sign */;

// As a promise
check(signature).spread(function(trusted, payload) {
    // trusted is true/false if signature is trusted/untrusted
    // payload is the payload of signature
});

// With a callback
check(signtaure, function(err, trusted, payload) {
   // err is an Error or falsy
});

// options: {
//   timeout: 1000, // ms
//   trustedListCacheTime: 3600, // seconds
//   additionalTrustedListURIs: [ 'https://somewhere.com/client-registration.json' ],
// }
// Using additional trusted lists
check(signature, { 
  additionalTrustedListURIs: [ 'https://somewhere.com/thelist.json' ]
})

## Trusted Lists ##
There are two types of external requests that this library will make.  First,
it will get a copy of the core "trusted list" and any additional ones passed
in the options.  It will cache these for default 1 hour.  The body returned
to the `GET` request should be an array of strings, with each string representing
a trusted URI that contains a set of json web keys (jwks = jwk set = json web key set).
These URI's are all the valid json web key uri `jku` that can be used in any given
JWT's header to indicate where to find the public key (`jwk`) that signed it.

*Example Trusted List:*
```javascript
request.get('https://sometrustedlist.com/list.json').then(result => {
  console.log('Request body for trusted list = ', result.body);
});
// Prints to the console:
// Request body for trusted list = 
// [
//   'https://somewhere.com/jwkset.json',
//   'https://somewhereelse.com/oursetofjsonwebkeys.json'
// ]
```

## JSON Web Key Set ##
The second type of external request that this library will make is to get the 
set of approved json web keys from all the URL's listed in all of the trusted
lists.  Abbreviated as `jwks` in the standard, a jwks is a valid JSON object 
that contains a key named "keys", at which is an array of valid keys.

*Example JWKS:*
```javascript
request.get('https://sometrustedlist.com/jwks.json').then(result => {
  console.log('Request body for jwks = ', result.body);
});
// Prints to the console:
// Request body for jwks = 
// {
//   "keys": [
//     {
//       "alg": "RS256",
//       "use": "sig",
//       "kid": "kjcScjc32dwJXXLJDs3r124sa1",
//       "kty": "RSA",
//       "n": "359ZykLITko_McOOKAtpJRVkjS5itwZxzjQidW2X6tBEOYCH4LZbwfj8fGGvlUtzpyuwnYuIlNX8TvZLTenOk45pphXr5PMCMKi7YZgkhd6_t_oeHnXY-4bnDLF1r9OUFKwj6C-mFFM-woKc-62tuK6QJiuc-5bFfn9wRL15K1E",
//       "e": "AQAB"
//     }
//   ]
// }
```



