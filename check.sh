#!/bin/sh

./node_modules/jshint/bin/jshint --show-non-errors main.js
./node_modules/.bin/eslint main.js

./node_modules/jshint/bin/jshint --show-non-errors crl.js
./node_modules/.bin/eslint crl.js
