[![Build Status](https://travis-ci.org/OADA/oada-trusted-jws-js.svg?branch=master)](https://travis-ci.org/OADA/oada-trusted-jws-js)
[![Coverage Status](https://coveralls.io/repos/OADA/oada-trusted-jws-js/badge.svg?branch=master)](https://coveralls.io/r/OADA/oada-trusted-jws-js?branch=master)
[![Dependency Status](https://david-dm.org/oada/oada-trusted-jws-js.svg)](https://david-dm.org/oada/oada-trusted-jws-js)
[![License](http://img.shields.io/:license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

# oada-trusted-jws #

## Installation ##
```shell
npm install oada-trusted-jws
```

## Usage ##
```javascript
var check = require('oada-trusted-jws');

var signature = /* Get there from somewhere */;

// As a promise
check(signature).spread(function(trusted, payload) {
    // trusted is true/false if signature is trusted/untrused
    // payload is the payload of signature
});

// With a callback
check(signtaure, function(err, trusted, payload) {
   // err is an Error or falsy
});
```
