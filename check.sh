#!/bin/sh

jshint --show-non-errors main.js
eslint main.js

jshint --show-non-errors crl.js
eslint crl.js
