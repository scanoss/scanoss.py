/*
 * Copyright (c) 2023 Express Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

const http = require('http');
const path = require('path');
const fs = require('fs');

const DEFAULT_PORT = 3000;
const DEFAULT_HOST = '127.0.0.1';

class Server {
  constructor(options = {}) {
    this.port = options.port || DEFAULT_PORT;
    this.host = options.host || DEFAULT_HOST;
    this.routes = new Map();
    this.middleware = [];
  }

  use(fn) {
    if (typeof fn !== 'function') {
      throw new TypeError('Middleware must be a function');
    }
    this.middleware.push(fn);
    return this;
  }

  get(path, handler) {
    this.routes.set(`GET:${path}`, handler);
    return this;
  }

  post(path, handler) {
    this.routes.set(`POST:${path}`, handler);
    return this;
  }

  listen(callback) {
    this.server = http.createServer((req, res) => {
      this._handleRequest(req, res);
    });

    this.server.listen(this.port, this.host, () => {
      if (callback) callback(this.port, this.host);
    });

    return this;
  }

  _handleRequest(req, res) {
    const key = `${req.method}:${req.url}`;
    const handler = this.routes.get(key);

    if (handler) {
      handler(req, res);
    } else {
      res.statusCode = 404;
      res.end('Not Found');
    }
  }

  close() {
    if (this.server) {
      this.server.close();
    }
  }
}

module.exports = Server;