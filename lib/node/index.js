"use strict";

function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Module dependencies.
 */
// eslint-disable-next-line node/no-deprecated-api
var _require = require('url'),
    parse = _require.parse,
    format = _require.format,
    resolve = _require.resolve;

var Stream = require('stream');

var https = require('https');

var http = require('http');

var fs = require('fs');

var zlib = require('zlib');

var util = require('util');

var qs = require('qs');

var mime = require('mime');

var methods = require('methods');

var FormData = require('form-data');

var formidable = require('formidable');

var debug = require('debug')('superagent');

var CookieJar = require('cookiejar');

var semver = require('semver');

var safeStringify = require('fast-safe-stringify');

var utils = require('../utils');

var RequestBase = require('../request-base');

var _require2 = require('./unzip'),
    unzip = _require2.unzip;

var Response = require('./response');

var http2;
if (semver.gte(process.version, 'v10.10.0')) http2 = require('./http2wrapper');

function request(method, url) {
  // callback
  if (typeof url === 'function') {
    return new exports.Request('GET', method).end(url);
  } // url first


  if (arguments.length === 1) {
    return new exports.Request('GET', method);
  }

  return new exports.Request(method, url);
}

module.exports = request;
exports = module.exports;
/**
 * Expose `Request`.
 */

exports.Request = Request;
/**
 * Expose the agent function
 */

exports.agent = require('./agent');
/**
 * Noop.
 */

function noop() {}
/**
 * Expose `Response`.
 */


exports.Response = Response;
/**
 * Define "form" mime type.
 */

mime.define({
  'application/x-www-form-urlencoded': ['form', 'urlencoded', 'form-data']
}, true);
/**
 * Protocol map.
 */

exports.protocols = {
  'http:': http,
  'https:': https,
  'http2:': http2
};
/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

exports.serialize = {
  'application/x-www-form-urlencoded': qs.stringify,
  'application/json': safeStringify
};
/**
 * Default parsers.
 *
 *     superagent.parse['application/xml'] = function(res, fn){
 *       fn(null, res);
 *     };
 *
 */

exports.parse = require('./parsers');
/**
 * Default buffering map. Can be used to set certain
 * response types to buffer/not buffer.
 *
 *     superagent.buffer['application/xml'] = true;
 */

exports.buffer = {};
/**
 * Initialize internal header tracking properties on a request instance.
 *
 * @param {Object} req the instance
 * @api private
 */

function _initHeaders(req) {
  req._header = {// coerces header names to lowercase
  };
  req.header = {// preserves header name case
  };
}
/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String|Object} url
 * @api public
 */


function Request(method, url) {
  Stream.call(this);
  if (typeof url !== 'string') url = format(url);
  this._enableHttp2 = Boolean(process.env.HTTP2_TEST); // internal only

  this._agent = false;
  this._formData = null;
  this.method = method;
  this.url = url;

  _initHeaders(this);

  this.writable = true;
  this._redirects = 0;
  this.redirects(method === 'HEAD' ? 0 : 5);
  this.cookies = '';
  this.qs = {};
  this._query = [];
  this.qsRaw = this._query; // Unused, for backwards compatibility only

  this._redirectList = [];
  this._streamRequest = false;
  this.once('end', this.clearTimeout.bind(this));
}
/**
 * Inherit from `Stream` (which inherits from `EventEmitter`).
 * Mixin `RequestBase`.
 */


util.inherits(Request, Stream); // eslint-disable-next-line new-cap

RequestBase(Request.prototype);
/**
 * Enable or Disable http2.
 *
 * Enable http2.
 *
 * ``` js
 * request.get('http://localhost/')
 *   .http2()
 *   .end(callback);
 *
 * request.get('http://localhost/')
 *   .http2(true)
 *   .end(callback);
 * ```
 *
 * Disable http2.
 *
 * ``` js
 * request = request.http2();
 * request.get('http://localhost/')
 *   .http2(false)
 *   .end(callback);
 * ```
 *
 * @param {Boolean} enable
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.http2 = function (bool) {
  if (exports.protocols['http2:'] === undefined) {
    throw new Error('superagent: this version of Node.js does not support http2');
  }

  this._enableHttp2 = bool === undefined ? true : bool;
  return this;
};
/**
 * Queue the given `file` as an attachment to the specified `field`,
 * with optional `options` (or filename).
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('field', Buffer.from('<b>Hello world</b>'), 'hello.html')
 *   .end(callback);
 * ```
 *
 * A filename may also be used:
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('files', 'image.jpg')
 *   .end(callback);
 * ```
 *
 * @param {String} field
 * @param {String|fs.ReadStream|Buffer} file
 * @param {String|Object} options
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.attach = function (field, file, options) {
  if (file) {
    if (this._data) {
      throw new Error("superagent can't mix .send() and .attach()");
    }

    var o = options || {};

    if (typeof options === 'string') {
      o = {
        filename: options
      };
    }

    if (typeof file === 'string') {
      if (!o.filename) o.filename = file;
      debug('creating `fs.ReadStream` instance for file: %s', file);
      file = fs.createReadStream(file);
    } else if (!o.filename && file.path) {
      o.filename = file.path;
    }

    this._getFormData().append(field, file, o);
  }

  return this;
};

Request.prototype._getFormData = function () {
  var _this = this;

  if (!this._formData) {
    this._formData = new FormData();

    this._formData.on('error', function (err) {
      debug('FormData error', err);

      if (_this.called) {
        // The request has already finished and the callback was called.
        // Silently ignore the error.
        return;
      }

      _this.callback(err);

      _this.abort();
    });
  }

  return this._formData;
};
/**
 * Gets/sets the `Agent` to use for this HTTP request. The default (if this
 * function is not called) is to opt out of connection pooling (`agent: false`).
 *
 * @param {http.Agent} agent
 * @return {http.Agent}
 * @api public
 */


Request.prototype.agent = function (agent) {
  if (arguments.length === 0) return this._agent;
  this._agent = agent;
  return this;
};
/**
 * Set _Content-Type_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.type = function (type) {
  return this.set('Content-Type', type.includes('/') ? type : mime.getType(type));
};
/**
 * Set _Accept_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      superagent.types.json = 'application/json';
 *
 *      request.get('/agent')
 *        .accept('json')
 *        .end(callback);
 *
 *      request.get('/agent')
 *        .accept('application/json')
 *        .end(callback);
 *
 * @param {String} accept
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.accept = function (type) {
  return this.set('Accept', type.includes('/') ? type : mime.getType(type));
};
/**
 * Add query-string `val`.
 *
 * Examples:
 *
 *   request.get('/shoes')
 *     .query('size=10')
 *     .query({ color: 'blue' })
 *
 * @param {Object|String} val
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.query = function (val) {
  if (typeof val === 'string') {
    this._query.push(val);
  } else {
    Object.assign(this.qs, val);
  }

  return this;
};
/**
 * Write raw `data` / `encoding` to the socket.
 *
 * @param {Buffer|String} data
 * @param {String} encoding
 * @return {Boolean}
 * @api public
 */


Request.prototype.write = function (data, encoding) {
  var req = this.request();

  if (!this._streamRequest) {
    this._streamRequest = true;
  }

  return req.write(data, encoding);
};
/**
 * Pipe the request body to `stream`.
 *
 * @param {Stream} stream
 * @param {Object} options
 * @return {Stream}
 * @api public
 */


Request.prototype.pipe = function (stream, options) {
  this.piped = true; // HACK...

  this.buffer(false);
  this.end();
  return this._pipeContinue(stream, options);
};

Request.prototype._pipeContinue = function (stream, options) {
  var _this2 = this;

  this.req.once('response', function (res) {
    // redirect
    if (isRedirect(res.statusCode) && _this2._redirects++ !== _this2._maxRedirects) {
      return _this2._redirect(res) === _this2 ? _this2._pipeContinue(stream, options) : undefined;
    }

    _this2.res = res;

    _this2._emitResponse();

    if (_this2._aborted) return;

    if (_this2._shouldUnzip(res)) {
      var unzipObj = zlib.createUnzip();
      unzipObj.on('error', function (err) {
        if (err && err.code === 'Z_BUF_ERROR') {
          // unexpected end of file is ignored by browsers and curl
          stream.emit('end');
          return;
        }

        stream.emit('error', err);
      });
      res.pipe(unzipObj).pipe(stream, options);
    } else {
      res.pipe(stream, options);
    }

    res.once('end', function () {
      _this2.emit('end');
    });
  });
  return stream;
};
/**
 * Enable / disable buffering.
 *
 * @return {Boolean} [val]
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.buffer = function (val) {
  this._buffer = val !== false;
  return this;
};
/**
 * Redirect to `url
 *
 * @param {IncomingMessage} res
 * @return {Request} for chaining
 * @api private
 */


Request.prototype._redirect = function (res) {
  var url = res.headers.location;

  if (!url) {
    return this.callback(new Error('No location header for redirect'), res);
  }

  debug('redirect %s -> %s', this.url, url); // location

  url = resolve(this.url, url); // ensure the response is being consumed
  // this is required for Node v0.10+

  res.resume();
  var headers = this.req.getHeaders ? this.req.getHeaders() : this.req._headers;
  var changesOrigin = parse(url).host !== parse(this.url).host; // implementation of 302 following defacto standard

  if (res.statusCode === 301 || res.statusCode === 302) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin); // force GET

    this.method = this.method === 'HEAD' ? 'HEAD' : 'GET'; // clear data

    this._data = null;
  } // 303 is always GET


  if (res.statusCode === 303) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin); // force method

    this.method = 'GET'; // clear data

    this._data = null;
  } // 307 preserves method
  // 308 preserves method


  delete headers.host;
  delete this.req;
  delete this._formData; // remove all add header except User-Agent

  _initHeaders(this); // redirect


  this._endCalled = false;
  this.url = url;
  this.qs = {};
  this._query.length = 0;
  this.set(headers);
  this.emit('redirect', res);

  this._redirectList.push(this.url);

  this.end(this._callback);
  return this;
};
/**
 * Set Authorization field value with `user` and `pass`.
 *
 * Examples:
 *
 *   .auth('tobi', 'learnboost')
 *   .auth('tobi:learnboost')
 *   .auth('tobi')
 *   .auth(accessToken, { type: 'bearer' })
 *
 * @param {String} user
 * @param {String} [pass]
 * @param {Object} [options] options with authorization type 'basic' or 'bearer' ('basic' is default)
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.auth = function (user, pass, options) {
  if (arguments.length === 1) pass = '';

  if (_typeof(pass) === 'object' && pass !== null) {
    // pass is optional and can be replaced with options
    options = pass;
    pass = '';
  }

  if (!options) {
    options = {
      type: 'basic'
    };
  }

  var encoder = function encoder(string) {
    return Buffer.from(string).toString('base64');
  };

  return this._auth(user, pass, options, encoder);
};
/**
 * Set the certificate authority option for https request.
 *
 * @param {Buffer | Array} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.ca = function (cert) {
  this._ca = cert;
  return this;
};
/**
 * Set the client certificate key option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.key = function (cert) {
  this._key = cert;
  return this;
};
/**
 * Set the key, certificate, and CA certs of the client in PFX or PKCS12 format.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.pfx = function (cert) {
  if (_typeof(cert) === 'object' && !Buffer.isBuffer(cert)) {
    this._pfx = cert.pfx;
    this._passphrase = cert.passphrase;
  } else {
    this._pfx = cert;
  }

  return this;
};
/**
 * Set the client certificate option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.cert = function (cert) {
  this._cert = cert;
  return this;
};
/**
 * Do not reject expired or invalid TLS certs.
 * sets `rejectUnauthorized=true`. Be warned that this allows MITM attacks.
 *
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.disableTLSCerts = function () {
  this._disableTLSCerts = true;
  return this;
};
/**
 * Return an http[s] request.
 *
 * @return {OutgoingMessage}
 * @api private
 */
// eslint-disable-next-line complexity


Request.prototype.request = function () {
  var _this3 = this;

  if (this.req) return this.req;
  var options = {};

  try {
    var query = qs.stringify(this.qs, {
      indices: false,
      strictNullHandling: true
    });

    if (query) {
      this.qs = {};

      this._query.push(query);
    }

    this._finalizeQueryString();
  } catch (err) {
    return this.emit('error', err);
  }

  var url = this.url;
  var retries = this._retries; // Capture backticks as-is from the final query string built above.
  // Note: this'll only find backticks entered in req.query(String)
  // calls, because qs.stringify unconditionally encodes backticks.

  var queryStringBackticks;

  if (url.includes('`')) {
    var queryStartIndex = url.indexOf('?');

    if (queryStartIndex !== -1) {
      var queryString = url.slice(queryStartIndex + 1);
      queryStringBackticks = queryString.match(/`|%60/g);
    }
  } // default to http://


  if (url.indexOf('http') !== 0) url = "http://".concat(url);
  url = parse(url); // See https://github.com/visionmedia/superagent/issues/1367

  if (queryStringBackticks) {
    var i = 0;
    url.query = url.query.replace(/%60/g, function () {
      return queryStringBackticks[i++];
    });
    url.search = "?".concat(url.query);
    url.path = url.pathname + url.search;
  } // support unix sockets


  if (/^https?\+unix:/.test(url.protocol) === true) {
    // get the protocol
    url.protocol = "".concat(url.protocol.split('+')[0], ":"); // get the socket, path

    var unixParts = url.path.match(/^([^/]+)(.+)$/);
    options.socketPath = unixParts[1].replace(/%2F/g, '/');
    url.path = unixParts[2];
  } // Override IP address of a hostname


  if (this._connectOverride) {
    var _url = url,
        hostname = _url.hostname;
    var match = hostname in this._connectOverride ? this._connectOverride[hostname] : this._connectOverride['*'];

    if (match) {
      // backup the real host
      if (!this._header.host) {
        this.set('host', url.host);
      } // wrap [ipv6]


      url.host = /:/.test(match) ? "[".concat(match, "]") : match;

      if (url.port) {
        url.host += ":".concat(url.port);
      }

      url.hostname = match;
    }
  } // options


  options.method = this.method;
  options.port = url.port;
  options.path = url.path;
  options.host = url.hostname;
  options.ca = this._ca;
  options.key = this._key;
  options.pfx = this._pfx;
  options.cert = this._cert;
  options.passphrase = this._passphrase;
  options.agent = this._agent;
  options.rejectUnauthorized = typeof this._disableTLSCerts === 'boolean' ? !this._disableTLSCerts : process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0'; // Allows request.get('https://1.2.3.4/').set('Host', 'example.com')

  if (this._header.host) {
    options.servername = this._header.host.replace(/:\d+$/, '');
  }

  if (this._trustLocalhost && /^(?:localhost|127\.0\.0\.\d+|(0*:)+:0*1)$/.test(url.hostname)) {
    options.rejectUnauthorized = false;
  } // initiate request


  var mod = this._enableHttp2 ? exports.protocols['http2:'].setProtocol(url.protocol) : exports.protocols[url.protocol]; // request

  this.req = mod.request(options);
  var req = this.req; // set tcp no delay

  req.setNoDelay(true);

  if (options.method !== 'HEAD') {
    req.setHeader('Accept-Encoding', 'gzip, deflate');
  }

  this.protocol = url.protocol;
  this.host = url.host; // expose events

  req.once('drain', function () {
    _this3.emit('drain');
  });
  req.on('error', function (err) {
    // flag abortion here for out timeouts
    // because node will emit a faux-error "socket hang up"
    // when request is aborted before a connection is made
    if (_this3._aborted) return; // if not the same, we are in the **old** (cancelled) request,
    // so need to continue (same as for above)

    if (_this3._retries !== retries) return; // if we've received a response then we don't want to let
    // an error in the request blow up the response

    if (_this3.response) return;

    _this3.callback(err);
  }); // auth

  if (url.auth) {
    var auth = url.auth.split(':');
    this.auth(auth[0], auth[1]);
  }

  if (this.username && this.password) {
    this.auth(this.username, this.password);
  }

  for (var key in this.header) {
    if (Object.prototype.hasOwnProperty.call(this.header, key)) req.setHeader(key, this.header[key]);
  } // add cookies


  if (this.cookies) {
    if (Object.prototype.hasOwnProperty.call(this._header, 'cookie')) {
      // merge
      var tmpJar = new CookieJar.CookieJar();
      tmpJar.setCookies(this._header.cookie.split(';'));
      tmpJar.setCookies(this.cookies.split(';'));
      req.setHeader('Cookie', tmpJar.getCookies(CookieJar.CookieAccessInfo.All).toValueString());
    } else {
      req.setHeader('Cookie', this.cookies);
    }
  }

  return req;
};
/**
 * Invoke the callback with `err` and `res`
 * and handle arity check.
 *
 * @param {Error} err
 * @param {Response} res
 * @api private
 */


Request.prototype.callback = function (err, res) {
  if (this._shouldRetry(err, res)) {
    return this._retry();
  } // Avoid the error which is emitted from 'socket hang up' to cause the fn undefined error on JS runtime.


  var fn = this._callback || noop;
  this.clearTimeout();
  if (this.called) return console.warn('superagent: double callback bug');
  this.called = true;

  if (!err) {
    try {
      if (!this._isResponseOK(res)) {
        var msg = 'Unsuccessful HTTP response';

        if (res) {
          msg = http.STATUS_CODES[res.status] || msg;
        }

        err = new Error(msg);
        err.status = res ? res.status : undefined;
      }
    } catch (err_) {
      err = err_;
    }
  } // It's important that the callback is called outside try/catch
  // to avoid double callback


  if (!err) {
    return fn(null, res);
  }

  err.response = res;
  err.url = this.url;
  if (this._maxRetries) err.retries = this._retries - 1; // only emit error event if there is a listener
  // otherwise we assume the callback to `.end()` will get the error

  if (err && this.listeners('error').length > 0) {
    this.emit('error', err);
  }

  fn(err, res);
};
/**
 * Check if `obj` is a host object,
 *
 * @param {Object} obj host object
 * @return {Boolean} is a host object
 * @api private
 */


Request.prototype._isHost = function (obj) {
  return Buffer.isBuffer(obj) || obj instanceof Stream || obj instanceof FormData;
};
/**
 * Initiate request, invoking callback `fn(err, res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */


Request.prototype._emitResponse = function (body, files) {
  var response = new Response(this);
  this.response = response;
  response.redirects = this._redirectList;

  if (undefined !== body) {
    response.body = body;
  }

  response.files = files;

  if (this._endCalled) {
    response.pipe = function () {
      throw new Error("end() has already been called, so it's too late to start piping");
    };
  }

  this.emit('response', response);
  return response;
};

Request.prototype.end = function (fn) {
  this.request();
  debug('%s %s', this.method, this.url);

  if (this._endCalled) {
    throw new Error('.end() was called twice. This is not supported in superagent');
  }

  this._endCalled = true; // store callback

  this._callback = fn || noop;

  this._end();
};

Request.prototype._end = function () {
  var _this4 = this;

  if (this._aborted) return this.callback(new Error('The request has been aborted even before .end() was called'));
  var data = this._data;
  var req = this.req;
  var method = this.method;

  this._setTimeouts(); // body


  if (method !== 'HEAD' && !req._headerSent) {
    // serialize stuff
    if (typeof data !== 'string') {
      var contentType = req.getHeader('Content-Type'); // Parse out just the content type from the header (ignore the charset)

      if (contentType) contentType = contentType.split(';')[0];
      var serialize = this._serializer || exports.serialize[contentType];

      if (!serialize && isJSON(contentType)) {
        serialize = exports.serialize['application/json'];
      }

      if (serialize) data = serialize(data);
    } // content-length


    if (data && !req.getHeader('Content-Length')) {
      req.setHeader('Content-Length', Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data));
    }
  } // response
  // eslint-disable-next-line complexity


  req.once('response', function (res) {
    debug('%s %s -> %s', _this4.method, _this4.url, res.statusCode);

    if (_this4._responseTimeoutTimer) {
      clearTimeout(_this4._responseTimeoutTimer);
    }

    if (_this4.piped) {
      return;
    }

    var max = _this4._maxRedirects;
    var mime = utils.type(res.headers['content-type'] || '') || 'text/plain';
    var type = mime.split('/')[0];
    var multipart = type === 'multipart';
    var redirect = isRedirect(res.statusCode);
    var responseType = _this4._responseType;
    _this4.res = res; // redirect

    if (redirect && _this4._redirects++ !== max) {
      return _this4._redirect(res);
    }

    if (_this4.method === 'HEAD') {
      _this4.emit('end');

      _this4.callback(null, _this4._emitResponse());

      return;
    } // zlib support


    if (_this4._shouldUnzip(res)) {
      unzip(req, res);
    }

    var buffer = _this4._buffer;

    if (buffer === undefined && mime in exports.buffer) {
      buffer = Boolean(exports.buffer[mime]);
    }

    var parser = _this4._parser;

    if (undefined === buffer) {
      if (parser) {
        console.warn("A custom superagent parser has been set, but buffering strategy for the parser hasn't been configured. Call `req.buffer(true or false)` or set `superagent.buffer[mime] = true or false`");
        buffer = true;
      }
    }

    if (!parser) {
      if (responseType) {
        parser = exports.parse.image; // It's actually a generic Buffer

        buffer = true;
      } else if (multipart) {
        var form = new formidable.IncomingForm();
        parser = form.parse.bind(form);
        buffer = true;
      } else if (isImageOrVideo(mime)) {
        parser = exports.parse.image;
        buffer = true; // For backwards-compatibility buffering default is ad-hoc MIME-dependent
      } else if (exports.parse[mime]) {
        parser = exports.parse[mime];
      } else if (type === 'text') {
        parser = exports.parse.text;
        buffer = buffer !== false; // everyone wants their own white-labeled json
      } else if (isJSON(mime)) {
        parser = exports.parse['application/json'];
        buffer = buffer !== false;
      } else if (buffer) {
        parser = exports.parse.text;
      } else if (undefined === buffer) {
        parser = exports.parse.image; // It's actually a generic Buffer

        buffer = true;
      }
    } // by default only buffer text/*, json and messed up thing from hell


    if (undefined === buffer && isText(mime) || isJSON(mime)) {
      buffer = true;
    }

    _this4._resBuffered = buffer;
    var parserHandlesEnd = false;

    if (buffer) {
      // Protectiona against zip bombs and other nuisance
      var responseBytesLeft = _this4._maxResponseSize || 200000000;
      res.on('data', function (buf) {
        responseBytesLeft -= buf.byteLength || buf.length;

        if (responseBytesLeft < 0) {
          // This will propagate through error event
          var err = new Error('Maximum response size reached');
          err.code = 'ETOOLARGE'; // Parsers aren't required to observe error event,
          // so would incorrectly report success

          parserHandlesEnd = false; // Will emit error event

          res.destroy(err);
        }
      });
    }

    if (parser) {
      try {
        // Unbuffered parsers are supposed to emit response early,
        // which is weird BTW, because response.body won't be there.
        parserHandlesEnd = buffer;
        parser(res, function (err, obj, files) {
          if (_this4.timedout) {
            // Timeout has already handled all callbacks
            return;
          } // Intentional (non-timeout) abort is supposed to preserve partial response,
          // even if it doesn't parse.


          if (err && !_this4._aborted) {
            return _this4.callback(err);
          }

          if (parserHandlesEnd) {
            _this4.emit('end');

            _this4.callback(null, _this4._emitResponse(obj, files));
          }
        });
      } catch (err) {
        _this4.callback(err);

        return;
      }
    }

    _this4.res = res; // unbuffered

    if (!buffer) {
      debug('unbuffered %s %s', _this4.method, _this4.url);

      _this4.callback(null, _this4._emitResponse());

      if (multipart) return; // allow multipart to handle end event

      res.once('end', function () {
        debug('end %s %s', _this4.method, _this4.url);

        _this4.emit('end');
      });
      return;
    } // terminating events


    res.once('error', function (err) {
      parserHandlesEnd = false;

      _this4.callback(err, null);
    });
    if (!parserHandlesEnd) res.once('end', function () {
      debug('end %s %s', _this4.method, _this4.url); // TODO: unless buffering emit earlier to stream

      _this4.emit('end');

      _this4.callback(null, _this4._emitResponse());
    });
  });
  this.emit('request', this);

  var getProgressMonitor = function getProgressMonitor() {
    var lengthComputable = true;
    var total = req.getHeader('Content-Length');
    var loaded = 0;
    var progress = new Stream.Transform();

    progress._transform = function (chunk, encoding, cb) {
      loaded += chunk.length;

      _this4.emit('progress', {
        direction: 'upload',
        lengthComputable: lengthComputable,
        loaded: loaded,
        total: total
      });

      cb(null, chunk);
    };

    return progress;
  };

  var bufferToChunks = function bufferToChunks(buffer) {
    var chunkSize = 16 * 1024; // default highWaterMark value

    var chunking = new Stream.Readable();
    var totalLength = buffer.length;
    var remainder = totalLength % chunkSize;
    var cutoff = totalLength - remainder;

    for (var i = 0; i < cutoff; i += chunkSize) {
      var chunk = buffer.slice(i, i + chunkSize);
      chunking.push(chunk);
    }

    if (remainder > 0) {
      var remainderBuffer = buffer.slice(-remainder);
      chunking.push(remainderBuffer);
    }

    chunking.push(null); // no more data

    return chunking;
  }; // if a FormData instance got created, then we send that as the request body


  var formData = this._formData;

  if (formData) {
    // set headers
    var headers = formData.getHeaders();

    for (var i in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, i)) {
        debug('setting FormData header: "%s: %s"', i, headers[i]);
        req.setHeader(i, headers[i]);
      }
    } // attempt to get "Content-Length" header
    // eslint-disable-next-line handle-callback-err


    formData.getLength(function (err, length) {
      // TODO: Add chunked encoding when no length (if err)
      debug('got FormData Content-Length: %s', length);

      if (typeof length === 'number') {
        req.setHeader('Content-Length', length);
      }

      formData.pipe(getProgressMonitor()).pipe(req);
    });
  } else if (Buffer.isBuffer(data)) {
    bufferToChunks(data).pipe(getProgressMonitor()).pipe(req);
  } else {
    req.end(data);
  }
}; // Check whether response has a non-0-sized gzip-encoded body


Request.prototype._shouldUnzip = function (res) {
  if (res.statusCode === 204 || res.statusCode === 304) {
    // These aren't supposed to have any body
    return false;
  } // header content is a string, and distinction between 0 and no information is crucial


  if (res.headers['content-length'] === '0') {
    // We know that the body is empty (unfortunately, this check does not cover chunked encoding)
    return false;
  } // console.log(res);


  return /^\s*(?:deflate|gzip)\s*$/.test(res.headers['content-encoding']);
};
/**
 * Overrides DNS for selected hostnames. Takes object mapping hostnames to IP addresses.
 *
 * When making a request to a URL with a hostname exactly matching a key in the object,
 * use the given IP address to connect, instead of using DNS to resolve the hostname.
 *
 * A special host `*` matches every hostname (keep redirects in mind!)
 *
 *      request.connect({
 *        'test.example.com': '127.0.0.1',
 *        'ipv6.example.com': '::1',
 *      })
 */


Request.prototype.connect = function (connectOverride) {
  if (typeof connectOverride === 'string') {
    this._connectOverride = {
      '*': connectOverride
    };
  } else if (_typeof(connectOverride) === 'object') {
    this._connectOverride = connectOverride;
  } else {
    this._connectOverride = undefined;
  }

  return this;
};

Request.prototype.trustLocalhost = function (toggle) {
  this._trustLocalhost = toggle === undefined ? true : toggle;
  return this;
}; // generate HTTP verb methods


if (!methods.includes('del')) {
  // create a copy so we don't cause conflicts with
  // other packages using the methods package and
  // npm 3.x
  methods = methods.slice(0);
  methods.push('del');
}

methods.forEach(function (method) {
  var name = method;
  method = method === 'del' ? 'delete' : method;
  method = method.toUpperCase();

  request[name] = function (url, data, fn) {
    var req = request(method, url);

    if (typeof data === 'function') {
      fn = data;
      data = null;
    }

    if (data) {
      if (method === 'GET' || method === 'HEAD') {
        req.query(data);
      } else {
        req.send(data);
      }
    }

    if (fn) req.end(fn);
    return req;
  };
});
/**
 * Check if `mime` is text and should be buffered.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api public
 */

function isText(mime) {
  var parts = mime.split('/');
  var type = parts[0];
  var subtype = parts[1];
  return type === 'text' || subtype === 'x-www-form-urlencoded';
}

function isImageOrVideo(mime) {
  var type = mime.split('/')[0];
  return type === 'image' || type === 'video';
}
/**
 * Check if `mime` is json or has +json structured syntax suffix.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api private
 */


function isJSON(mime) {
  // should match /json or +json
  // but not /json-seq
  return /[/+]json($|[^-\w])/.test(mime);
}
/**
 * Check if we should follow the redirect `code`.
 *
 * @param {Number} code
 * @return {Boolean}
 * @api private
 */


function isRedirect(code) {
  return [301, 302, 303, 305, 307, 308].includes(code);
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL2luZGV4LmpzIl0sIm5hbWVzIjpbInJlcXVpcmUiLCJwYXJzZSIsImZvcm1hdCIsInJlc29sdmUiLCJTdHJlYW0iLCJodHRwcyIsImh0dHAiLCJmcyIsInpsaWIiLCJ1dGlsIiwicXMiLCJtaW1lIiwibWV0aG9kcyIsIkZvcm1EYXRhIiwiZm9ybWlkYWJsZSIsImRlYnVnIiwiQ29va2llSmFyIiwic2VtdmVyIiwic2FmZVN0cmluZ2lmeSIsInV0aWxzIiwiUmVxdWVzdEJhc2UiLCJ1bnppcCIsIlJlc3BvbnNlIiwiaHR0cDIiLCJndGUiLCJwcm9jZXNzIiwidmVyc2lvbiIsInJlcXVlc3QiLCJtZXRob2QiLCJ1cmwiLCJleHBvcnRzIiwiUmVxdWVzdCIsImVuZCIsImFyZ3VtZW50cyIsImxlbmd0aCIsIm1vZHVsZSIsImFnZW50Iiwibm9vcCIsImRlZmluZSIsInByb3RvY29scyIsInNlcmlhbGl6ZSIsInN0cmluZ2lmeSIsImJ1ZmZlciIsIl9pbml0SGVhZGVycyIsInJlcSIsIl9oZWFkZXIiLCJoZWFkZXIiLCJjYWxsIiwiX2VuYWJsZUh0dHAyIiwiQm9vbGVhbiIsImVudiIsIkhUVFAyX1RFU1QiLCJfYWdlbnQiLCJfZm9ybURhdGEiLCJ3cml0YWJsZSIsIl9yZWRpcmVjdHMiLCJyZWRpcmVjdHMiLCJjb29raWVzIiwiX3F1ZXJ5IiwicXNSYXciLCJfcmVkaXJlY3RMaXN0IiwiX3N0cmVhbVJlcXVlc3QiLCJvbmNlIiwiY2xlYXJUaW1lb3V0IiwiYmluZCIsImluaGVyaXRzIiwicHJvdG90eXBlIiwiYm9vbCIsInVuZGVmaW5lZCIsIkVycm9yIiwiYXR0YWNoIiwiZmllbGQiLCJmaWxlIiwib3B0aW9ucyIsIl9kYXRhIiwibyIsImZpbGVuYW1lIiwiY3JlYXRlUmVhZFN0cmVhbSIsInBhdGgiLCJfZ2V0Rm9ybURhdGEiLCJhcHBlbmQiLCJvbiIsImVyciIsImNhbGxlZCIsImNhbGxiYWNrIiwiYWJvcnQiLCJ0eXBlIiwic2V0IiwiaW5jbHVkZXMiLCJnZXRUeXBlIiwiYWNjZXB0IiwicXVlcnkiLCJ2YWwiLCJwdXNoIiwiT2JqZWN0IiwiYXNzaWduIiwid3JpdGUiLCJkYXRhIiwiZW5jb2RpbmciLCJwaXBlIiwic3RyZWFtIiwicGlwZWQiLCJfcGlwZUNvbnRpbnVlIiwicmVzIiwiaXNSZWRpcmVjdCIsInN0YXR1c0NvZGUiLCJfbWF4UmVkaXJlY3RzIiwiX3JlZGlyZWN0IiwiX2VtaXRSZXNwb25zZSIsIl9hYm9ydGVkIiwiX3Nob3VsZFVuemlwIiwidW56aXBPYmoiLCJjcmVhdGVVbnppcCIsImNvZGUiLCJlbWl0IiwiX2J1ZmZlciIsImhlYWRlcnMiLCJsb2NhdGlvbiIsInJlc3VtZSIsImdldEhlYWRlcnMiLCJfaGVhZGVycyIsImNoYW5nZXNPcmlnaW4iLCJob3N0IiwiY2xlYW5IZWFkZXIiLCJfZW5kQ2FsbGVkIiwiX2NhbGxiYWNrIiwiYXV0aCIsInVzZXIiLCJwYXNzIiwiZW5jb2RlciIsInN0cmluZyIsIkJ1ZmZlciIsImZyb20iLCJ0b1N0cmluZyIsIl9hdXRoIiwiY2EiLCJjZXJ0IiwiX2NhIiwia2V5IiwiX2tleSIsInBmeCIsImlzQnVmZmVyIiwiX3BmeCIsIl9wYXNzcGhyYXNlIiwicGFzc3BocmFzZSIsIl9jZXJ0IiwiZGlzYWJsZVRMU0NlcnRzIiwiX2Rpc2FibGVUTFNDZXJ0cyIsImluZGljZXMiLCJzdHJpY3ROdWxsSGFuZGxpbmciLCJfZmluYWxpemVRdWVyeVN0cmluZyIsInJldHJpZXMiLCJfcmV0cmllcyIsInF1ZXJ5U3RyaW5nQmFja3RpY2tzIiwicXVlcnlTdGFydEluZGV4IiwiaW5kZXhPZiIsInF1ZXJ5U3RyaW5nIiwic2xpY2UiLCJtYXRjaCIsImkiLCJyZXBsYWNlIiwic2VhcmNoIiwicGF0aG5hbWUiLCJ0ZXN0IiwicHJvdG9jb2wiLCJzcGxpdCIsInVuaXhQYXJ0cyIsInNvY2tldFBhdGgiLCJfY29ubmVjdE92ZXJyaWRlIiwiaG9zdG5hbWUiLCJwb3J0IiwicmVqZWN0VW5hdXRob3JpemVkIiwiTk9ERV9UTFNfUkVKRUNUX1VOQVVUSE9SSVpFRCIsInNlcnZlcm5hbWUiLCJfdHJ1c3RMb2NhbGhvc3QiLCJtb2QiLCJzZXRQcm90b2NvbCIsInNldE5vRGVsYXkiLCJzZXRIZWFkZXIiLCJyZXNwb25zZSIsInVzZXJuYW1lIiwicGFzc3dvcmQiLCJoYXNPd25Qcm9wZXJ0eSIsInRtcEphciIsInNldENvb2tpZXMiLCJjb29raWUiLCJnZXRDb29raWVzIiwiQ29va2llQWNjZXNzSW5mbyIsIkFsbCIsInRvVmFsdWVTdHJpbmciLCJfc2hvdWxkUmV0cnkiLCJfcmV0cnkiLCJmbiIsImNvbnNvbGUiLCJ3YXJuIiwiX2lzUmVzcG9uc2VPSyIsIm1zZyIsIlNUQVRVU19DT0RFUyIsInN0YXR1cyIsImVycl8iLCJfbWF4UmV0cmllcyIsImxpc3RlbmVycyIsIl9pc0hvc3QiLCJvYmoiLCJib2R5IiwiZmlsZXMiLCJfZW5kIiwiX3NldFRpbWVvdXRzIiwiX2hlYWRlclNlbnQiLCJjb250ZW50VHlwZSIsImdldEhlYWRlciIsIl9zZXJpYWxpemVyIiwiaXNKU09OIiwiYnl0ZUxlbmd0aCIsIl9yZXNwb25zZVRpbWVvdXRUaW1lciIsIm1heCIsIm11bHRpcGFydCIsInJlZGlyZWN0IiwicmVzcG9uc2VUeXBlIiwiX3Jlc3BvbnNlVHlwZSIsInBhcnNlciIsIl9wYXJzZXIiLCJpbWFnZSIsImZvcm0iLCJJbmNvbWluZ0Zvcm0iLCJpc0ltYWdlT3JWaWRlbyIsInRleHQiLCJpc1RleHQiLCJfcmVzQnVmZmVyZWQiLCJwYXJzZXJIYW5kbGVzRW5kIiwicmVzcG9uc2VCeXRlc0xlZnQiLCJfbWF4UmVzcG9uc2VTaXplIiwiYnVmIiwiZGVzdHJveSIsInRpbWVkb3V0IiwiZ2V0UHJvZ3Jlc3NNb25pdG9yIiwibGVuZ3RoQ29tcHV0YWJsZSIsInRvdGFsIiwibG9hZGVkIiwicHJvZ3Jlc3MiLCJUcmFuc2Zvcm0iLCJfdHJhbnNmb3JtIiwiY2h1bmsiLCJjYiIsImRpcmVjdGlvbiIsImJ1ZmZlclRvQ2h1bmtzIiwiY2h1bmtTaXplIiwiY2h1bmtpbmciLCJSZWFkYWJsZSIsInRvdGFsTGVuZ3RoIiwicmVtYWluZGVyIiwiY3V0b2ZmIiwicmVtYWluZGVyQnVmZmVyIiwiZm9ybURhdGEiLCJnZXRMZW5ndGgiLCJjb25uZWN0IiwiY29ubmVjdE92ZXJyaWRlIiwidHJ1c3RMb2NhbGhvc3QiLCJ0b2dnbGUiLCJmb3JFYWNoIiwibmFtZSIsInRvVXBwZXJDYXNlIiwic2VuZCIsInBhcnRzIiwic3VidHlwZSJdLCJtYXBwaW5ncyI6Ijs7OztBQUFBOzs7QUFJQTtlQUNtQ0EsT0FBTyxDQUFDLEtBQUQsQztJQUFsQ0MsSyxZQUFBQSxLO0lBQU9DLE0sWUFBQUEsTTtJQUFRQyxPLFlBQUFBLE87O0FBQ3ZCLElBQU1DLE1BQU0sR0FBR0osT0FBTyxDQUFDLFFBQUQsQ0FBdEI7O0FBQ0EsSUFBTUssS0FBSyxHQUFHTCxPQUFPLENBQUMsT0FBRCxDQUFyQjs7QUFDQSxJQUFNTSxJQUFJLEdBQUdOLE9BQU8sQ0FBQyxNQUFELENBQXBCOztBQUNBLElBQU1PLEVBQUUsR0FBR1AsT0FBTyxDQUFDLElBQUQsQ0FBbEI7O0FBQ0EsSUFBTVEsSUFBSSxHQUFHUixPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFNUyxJQUFJLEdBQUdULE9BQU8sQ0FBQyxNQUFELENBQXBCOztBQUNBLElBQU1VLEVBQUUsR0FBR1YsT0FBTyxDQUFDLElBQUQsQ0FBbEI7O0FBQ0EsSUFBTVcsSUFBSSxHQUFHWCxPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFJWSxPQUFPLEdBQUdaLE9BQU8sQ0FBQyxTQUFELENBQXJCOztBQUNBLElBQU1hLFFBQVEsR0FBR2IsT0FBTyxDQUFDLFdBQUQsQ0FBeEI7O0FBQ0EsSUFBTWMsVUFBVSxHQUFHZCxPQUFPLENBQUMsWUFBRCxDQUExQjs7QUFDQSxJQUFNZSxLQUFLLEdBQUdmLE9BQU8sQ0FBQyxPQUFELENBQVAsQ0FBaUIsWUFBakIsQ0FBZDs7QUFDQSxJQUFNZ0IsU0FBUyxHQUFHaEIsT0FBTyxD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LEdBQU4sRUFBVyxHQUFYLEVBQWdCLEdBQWhCLEVBQXFCLEdBQXJCLEVBQTBCLEdBQTFCLEVBQStCekIsUUFBL0IsQ0FBd0N5QixJQUF4QyxDQUFQO0FBQ0QiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIE1vZHVsZSBkZXBlbmRlbmNpZXMuXG4gKi9cblxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vZGUvbm8tZGVwcmVjYXRlZC1hcGlcbmNvbnN0IHsgcGFyc2UsIGZvcm1hdCwgcmVzb2x2ZSB9ID0gcmVxdWlyZSgndXJsJyk7XG5jb25zdCBTdHJlYW0gPSByZXF1aXJlKCdzdHJlYW0nKTtcbmNvbnN0IGh0dHBzID0gcmVxdWlyZSgnaHR0cHMnKTtcbmNvbnN0IGh0dHAgPSByZXF1aXJlKCdodHRwJyk7XG5jb25zdCBmcyA9IHJlcXVpcmUoJ2ZzJyk7XG5jb25zdCB6bGliID0gcmVxdWlyZSgnemxpYicpO1xuY29uc3QgdXRpbCA9IHJlcXVpcmUoJ3V0aWwnKTtcbmNvbnN0IHFzID0gcmVxdWlyZSgncXMnKTtcbmNvbnN0IG1pbWUgPSByZXF1aXJlKCdtaW1lJyk7XG5sZXQgbWV0aG9kcyA9IHJlcXVpcmUoJ21ldGhvZHMnKTtcbmNvbnN0IEZvcm1EYXRhID0gcmVxdWlyZSgnZm9ybS1kYXRhJyk7XG5jb25zdCBmb3JtaWRhYmxlID0gcmVxdWlyZSgnZm9ybWlkYWJsZScpO1xuY29uc3QgZGVidWcgPSByZXF1aXJlKCdkZWJ1ZycpKCdzdXBlcmFnZW50Jyk7XG5jb25zdCBDb29raWVKYXIgPSByZXF1aXJlKCdjb29raWVqYXInKTtcbmNvbnN0IHNlbXZlciA9IHJlcXVpcmUoJ3NlbXZlcicpO1xuY29uc3Qgc2FmZVN0cmluZ2lmeSA9IHJlcXVpcmUoJ2Zhc3Qtc2FmZS1zdHJpbmdpZnknKTtcblxuY29uc3QgdXRpbHMgPSByZXF1aXJlKCcuLi91dGlscycpO1xuY29uc3QgUmVxdWVzdEJhc2UgPSByZXF1aXJlKCcuLi9yZXF1ZXN0LWJhc2UnKTtcbmNvbnN0IHsgdW56aXAgfSA9IHJlcXVpcmUoJy4vdW56aXAnKTtcbmNvbnN0IFJlc3BvbnNlID0gcmVxdWlyZSgnLi9yZXNwb25zZScpO1xuXG5sZXQgaHR0cDI7XG5cbmlmIChzZW12ZXIuZ3RlKHByb2Nlc3MudmVyc2lvbiwgJ3YxMC4xMC4wJykpIGh0dHAyID0gcmVxdWlyZSgnLi9odHRwMndyYXBwZXInKTtcblxuZnVuY3Rpb24gcmVxdWVzdChtZXRob2QsIHVybCkge1xuICAvLyBjYWxsYmFja1xuICBpZiAodHlwZW9mIHVybCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KCdHRVQnLCBtZXRob2QpLmVuZCh1cmwpO1xuICB9XG5cbiAgLy8gdXJsIGZpcnN0XG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QoJ0dFVCcsIG1ldGhvZCk7XG4gIH1cblxuICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdChtZXRob2QsIHVybCk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gcmVxdWVzdDtcbmV4cG9ydHMgPSBtb2R1bGUuZXhwb3J0cztcblxuLyoqXG4gKiBFeHBvc2UgYFJlcXVlc3RgLlxuICovXG5cbmV4cG9ydHMuUmVxdWVzdCA9IFJlcXVlc3Q7XG5cbi8qKlxuICogRXhwb3NlIHRoZSBhZ2VudCBmdW5jdGlvblxuICovXG5cbmV4cG9ydHMuYWdlbnQgPSByZXF1aXJlKCcuL2FnZW50Jyk7XG5cbi8qKlxuICogTm9vcC5cbiAqL1xuXG5mdW5jdGlvbiBub29wKCkge31cblxuLyoqXG4gKiBFeHBvc2UgYFJlc3BvbnNlYC5cbiAqL1xuXG5leHBvcnRzLlJlc3BvbnNlID0gUmVzcG9uc2U7XG5cbi8qKlxuICogRGVmaW5lIFwiZm9ybVwiIG1pbWUgdHlwZS5cbiAqL1xuXG5taW1lLmRlZmluZShcbiAge1xuICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnOiBbJ2Zvcm0nLCAndXJsZW5jb2RlZCcsICdmb3JtLWRhdGEnXVxuICB9LFxuICB0cnVlXG4pO1xuXG4vKipcbiAqIFByb3RvY29sIG1hcC5cbiAqL1xuXG5leHBvcnRzLnByb3RvY29scyA9IHtcbiAgJ2h0dHA6JzogaHR0cCxcbiAgJ2h0dHBzOic6IGh0dHBzLFxuICAnaHR0cDI6JzogaHR0cDJcbn07XG5cbi8qKlxuICogRGVmYXVsdCBzZXJpYWxpemF0aW9uIG1hcC5cbiAqXG4gKiAgICAgc3VwZXJhZ2VudC5zZXJpYWxpemVbJ2FwcGxpY2F0aW9uL3htbCddID0gZnVuY3Rpb24ob2JqKXtcbiAqICAgICAgIHJldHVybiAnZ2VuZXJhdGVkIHhtbCBoZXJlJztcbiAqICAgICB9O1xuICpcbiAqL1xuXG5leHBvcnRzLnNlcmlhbGl6ZSA9IHtcbiAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc6IHFzLnN0cmluZ2lmeSxcbiAgJ2FwcGxpY2F0aW9uL2pzb24nOiBzYWZlU3RyaW5naWZ5XG59O1xuXG4vKipcbiAqIERlZmF1bHQgcGFyc2Vycy5cbiAqXG4gKiAgICAgc3VwZXJhZ2VudC5wYXJzZVsnYXBwbGljYXRpb24veG1sJ10gPSBmdW5jdGlvbihyZXMsIGZuKXtcbiAqICAgICAgIGZuKG51bGwsIHJlcyk7XG4gKiAgICAgfTtcbiAqXG4gKi9cblxuZXhwb3J0cy5wYXJzZSA9IHJlcXVpcmUoJy4vcGFyc2VycycpO1xuXG4vKipcbiAqIERlZmF1bHQgYnVmZmVyaW5nIG1hcC4gQ2FuIGJlIHVzZWQgdG8gc2V0IGNlcnRhaW5cbiAqIHJlc3BvbnNlIHR5cGVzIHRvIGJ1ZmZlci9ub3QgYnVmZmVyLlxuICpcbiAqICAgICBzdXBlcmFnZW50LmJ1ZmZlclsnYXBwbGljYXRpb24veG1sJ10gPSB0cnVlO1xuICovXG5leHBvcnRzLmJ1ZmZlciA9IHt9O1xuXG4vKipcbiAqIEluaXRpYWxpemUgaW50ZXJuYWwgaGVhZGVyIHRyYWNraW5nIHByb3BlcnRpZXMgb24gYSByZXF1ZXN0IGluc3RhbmNlLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSByZXEgdGhlIGluc3RhbmNlXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuZnVuY3Rpb24gX2luaXRIZWFkZXJzKHJlcSkge1xuICByZXEuX2hlYWRlciA9IHtcbiAgICAvLyBjb2VyY2VzIGhlYWRlciBuYW1lcyB0byBsb3dlcmNhc2VcbiAgfTtcbiAgcmVxLmhlYWRlciA9IHtcbiAgICAvLyBwcmVzZXJ2ZXMgaGVhZGVyIG5hbWUgY2FzZVxuICB9O1xufVxuXG4vKipcbiAqIEluaXRpYWxpemUgYSBuZXcgYFJlcXVlc3RgIHdpdGggdGhlIGdpdmVuIGBtZXRob2RgIGFuZCBgdXJsYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gbWV0aG9kXG4gKiBAcGFyYW0ge1N0cmluZ3xPYmplY3R9IHVybFxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBSZXF1ZXN0KG1ldGhvZCwgdXJsKSB7XG4gIFN0cmVhbS5jYWxsKHRoaXMpO1xuICBpZiAodHlwZW9mIHVybCAhPT0gJ3N0cmluZycpIHVybCA9IGZvcm1hdCh1cmwpO1xuICB0aGlzLl9lbmFibGVIdHRwMiA9IEJvb2xlYW4ocHJvY2Vzcy5lbnYuSFRUUDJfVEVTVCk7IC8vIGludGVybmFsIG9ubHlcbiAgdGhpcy5fYWdlbnQgPSBmYWxzZTtcbiAgdGhpcy5fZm9ybURhdGEgPSBudWxsO1xuICB0aGlzLm1ldGhvZCA9IG1ldGhvZDtcbiAgdGhpcy51cmwgPSB1cmw7XG4gIF9pbml0SGVhZGVycyh0aGlzKTtcbiAgdGhpcy53cml0YWJsZSA9IHRydWU7XG4gIHRoaXMuX3JlZGlyZWN0cyA9IDA7XG4gIHRoaXMucmVkaXJlY3RzKG1ldGhvZCA9PT0gJ0hFQUQnID8gMCA6IDUpO1xuICB0aGlzLmNvb2tpZXMgPSAnJztcbiAgdGhpcy5xcyA9IHt9O1xuICB0aGlzLl9xdWVyeSA9IFtdO1xuICB0aGlzLnFzUmF3ID0gdGhpcy5fcXVlcnk7IC8vIFVudXNlZCwgZm9yIGJhY2t3YXJkcyBjb21wYXRpYmlsaXR5IG9ubHlcbiAgdGhpcy5fcmVkaXJlY3RMaXN0ID0gW107XG4gIHRoaXMuX3N0cmVhbVJlcXVlc3QgPSBmYWxzZTtcbiAgdGhpcy5vbmNlKCdlbmQnLCB0aGlzLmNsZWFyVGltZW91dC5iaW5kKHRoaXMpKTtcbn1cblxuLyoqXG4gKiBJbmhlcml0IGZyb20gYFN0cmVhbWAgKHdoaWNoIGluaGVyaXRzIGZyb20gYEV2ZW50RW1pdHRlcmApLlxuICogTWl4aW4gYFJlcXVlc3RCYXNlYC5cbiAqL1xudXRpbC5pbmhlcml0cyhSZXF1ZXN0LCBTdHJlYW0pO1xuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5ldy1jYXBcblJlcXVlc3RCYXNlKFJlcXVlc3QucHJvdG90eXBlKTtcblxuLyoqXG4gKiBFbmFibGUgb3IgRGlzYWJsZSBodHRwMi5cbiAqXG4gKiBFbmFibGUgaHR0cDIuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LmdldCgnaHR0cDovL2xvY2FsaG9zdC8nKVxuICogICAuaHR0cDIoKVxuICogICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiByZXF1ZXN0LmdldCgnaHR0cDovL2xvY2FsaG9zdC8nKVxuICogICAuaHR0cDIodHJ1ZSlcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBEaXNhYmxlIGh0dHAyLlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdCA9IHJlcXVlc3QuaHR0cDIoKTtcbiAqIHJlcXVlc3QuZ2V0KCdodHRwOi8vbG9jYWxob3N0LycpXG4gKiAgIC5odHRwMihmYWxzZSlcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBAcGFyYW0ge0Jvb2xlYW59IGVuYWJsZVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmh0dHAyID0gZnVuY3Rpb24oYm9vbCkge1xuICBpZiAoZXhwb3J0cy5wcm90b2NvbHNbJ2h0dHAyOiddID09PSB1bmRlZmluZWQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAnc3VwZXJhZ2VudDogdGhpcyB2ZXJzaW9uIG9mIE5vZGUuanMgZG9lcyBub3Qgc3VwcG9ydCBodHRwMidcbiAgICApO1xuICB9XG5cbiAgdGhpcy5fZW5hYmxlSHR0cDIgPSBib29sID09PSB1bmRlZmluZWQgPyB0cnVlIDogYm9vbDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFF1ZXVlIHRoZSBnaXZlbiBgZmlsZWAgYXMgYW4gYXR0YWNobWVudCB0byB0aGUgc3BlY2lmaWVkIGBmaWVsZGAsXG4gKiB3aXRoIG9wdGlvbmFsIGBvcHRpb25zYCAob3IgZmlsZW5hbWUpLlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdC5wb3N0KCdodHRwOi8vbG9jYWxob3N0L3VwbG9hZCcpXG4gKiAgIC5hdHRhY2goJ2ZpZWxkJywgQnVmZmVyLmZyb20oJzxiPkhlbGxvIHdvcmxkPC9iPicpLCAnaGVsbG8uaHRtbCcpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogQSBmaWxlbmFtZSBtYXkgYWxzbyBiZSB1c2VkOlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdC5wb3N0KCdodHRwOi8vbG9jYWxob3N0L3VwbG9hZCcpXG4gKiAgIC5hdHRhY2goJ2ZpbGVzJywgJ2ltYWdlLmpwZycpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGZpZWxkXG4gKiBAcGFyYW0ge1N0cmluZ3xmcy5SZWFkU3RyZWFtfEJ1ZmZlcn0gZmlsZVxuICogQHBhcmFtIHtTdHJpbmd8T2JqZWN0fSBvcHRpb25zXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYXR0YWNoID0gZnVuY3Rpb24oZmllbGQsIGZpbGUsIG9wdGlvbnMpIHtcbiAgaWYgKGZpbGUpIHtcbiAgICBpZiAodGhpcy5fZGF0YSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIGxldCBvID0gb3B0aW9ucyB8fCB7fTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBvID0geyBmaWxlbmFtZTogb3B0aW9ucyB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmlsZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICghby5maWxlbmFtZSkgby5maWxlbmFtZSA9IGZpbGU7XG4gICAgICBkZWJ1ZygnY3JlYXRpbmcgYGZzLlJlYWRTdHJlYW1gIGluc3RhbmNlIGZvciBmaWxlOiAlcycsIGZpbGUpO1xuICAgICAgZmlsZSA9IGZzLmNyZWF0ZVJlYWRTdHJlYW0oZmlsZSk7XG4gICAgfSBlbHNlIGlmICghby5maWxlbmFtZSAmJiBmaWxlLnBhdGgpIHtcbiAgICAgIG8uZmlsZW5hbWUgPSBmaWxlLnBhdGg7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmQoZmllbGQsIGZpbGUsIG8pO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fZ2V0Rm9ybURhdGEgPSBmdW5jdGlvbigpIHtcbiAgaWYgKCF0aGlzLl9mb3JtRGF0YSkge1xuICAgIHRoaXMuX2Zvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7XG4gICAgdGhpcy5fZm9ybURhdGEub24oJ2Vycm9yJywgZXJyID0+IHtcbiAgICAgIGRlYnVnKCdGb3JtRGF0YSBlcnJvcicsIGVycik7XG4gICAgICBpZiAodGhpcy5jYWxsZWQpIHtcbiAgICAgICAgLy8gVGhlIHJlcXVlc3QgaGFzIGFscmVhZHkgZmluaXNoZWQgYW5kIHRoZSBjYWxsYmFjayB3YXMgY2FsbGVkLlxuICAgICAgICAvLyBTaWxlbnRseSBpZ25vcmUgdGhlIGVycm9yLlxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgICAgIHRoaXMuYWJvcnQoKTtcbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLl9mb3JtRGF0YTtcbn07XG5cbi8qKlxuICogR2V0cy9zZXRzIHRoZSBgQWdlbnRgIHRvIHVzZSBmb3IgdGhpcyBIVFRQIHJlcXVlc3QuIFRoZSBkZWZhdWx0IChpZiB0aGlzXG4gKiBmdW5jdGlvbiBpcyBub3QgY2FsbGVkKSBpcyB0byBvcHQgb3V0IG9mIGNvbm5lY3Rpb24gcG9vbGluZyAoYGFnZW50OiBmYWxzZWApLlxuICpcbiAqIEBwYXJhbSB7aHR0cC5BZ2VudH0gYWdlbnRcbiAqIEByZXR1cm4ge2h0dHAuQWdlbnR9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmFnZW50ID0gZnVuY3Rpb24oYWdlbnQpIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDApIHJldHVybiB0aGlzLl9hZ2VudDtcbiAgdGhpcy5fYWdlbnQgPSBhZ2VudDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBfQ29udGVudC1UeXBlXyByZXNwb25zZSBoZWFkZXIgcGFzc2VkIHRocm91Z2ggYG1pbWUuZ2V0VHlwZSgpYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ3htbCcpXG4gKiAgICAgICAgLnNlbmQoeG1sc3RyaW5nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgnanNvbicpXG4gKiAgICAgICAgLnNlbmQoanNvbnN0cmluZylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ2FwcGxpY2F0aW9uL2pzb24nKVxuICogICAgICAgIC5zZW5kKGpzb25zdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHR5cGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS50eXBlID0gZnVuY3Rpb24odHlwZSkge1xuICByZXR1cm4gdGhpcy5zZXQoXG4gICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgdHlwZS5pbmNsdWRlcygnLycpID8gdHlwZSA6IG1pbWUuZ2V0VHlwZSh0eXBlKVxuICApO1xufTtcblxuLyoqXG4gKiBTZXQgX0FjY2VwdF8gcmVzcG9uc2UgaGVhZGVyIHBhc3NlZCB0aHJvdWdoIGBtaW1lLmdldFR5cGUoKWAuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAgICBzdXBlcmFnZW50LnR5cGVzLmpzb24gPSAnYXBwbGljYXRpb24vanNvbic7XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnL2FnZW50JylcbiAqICAgICAgICAuYWNjZXB0KCdqc29uJylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcXVlc3QuZ2V0KCcvYWdlbnQnKVxuICogICAgICAgIC5hY2NlcHQoJ2FwcGxpY2F0aW9uL2pzb24nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBhY2NlcHRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hY2NlcHQgPSBmdW5jdGlvbih0eXBlKSB7XG4gIHJldHVybiB0aGlzLnNldCgnQWNjZXB0JywgdHlwZS5pbmNsdWRlcygnLycpID8gdHlwZSA6IG1pbWUuZ2V0VHlwZSh0eXBlKSk7XG59O1xuXG4vKipcbiAqIEFkZCBxdWVyeS1zdHJpbmcgYHZhbGAuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICByZXF1ZXN0LmdldCgnL3Nob2VzJylcbiAqICAgICAucXVlcnkoJ3NpemU9MTAnKVxuICogICAgIC5xdWVyeSh7IGNvbG9yOiAnYmx1ZScgfSlcbiAqXG4gKiBAcGFyYW0ge09iamVjdHxTdHJpbmd9IHZhbFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnF1ZXJ5ID0gZnVuY3Rpb24odmFsKSB7XG4gIGlmICh0eXBlb2YgdmFsID09PSAnc3RyaW5nJykge1xuICAgIHRoaXMuX3F1ZXJ5LnB1c2godmFsKTtcbiAgfSBlbHNlIHtcbiAgICBPYmplY3QuYXNzaWduKHRoaXMucXMsIHZhbCk7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogV3JpdGUgcmF3IGBkYXRhYCAvIGBlbmNvZGluZ2AgdG8gdGhlIHNvY2tldC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlcnxTdHJpbmd9IGRhdGFcbiAqIEBwYXJhbSB7U3RyaW5nfSBlbmNvZGluZ1xuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUud3JpdGUgPSBmdW5jdGlvbihkYXRhLCBlbmNvZGluZykge1xuICBjb25zdCByZXEgPSB0aGlzLnJlcXVlc3QoKTtcbiAgaWYgKCF0aGlzLl9zdHJlYW1SZXF1ZXN0KSB7XG4gICAgdGhpcy5fc3RyZWFtUmVxdWVzdCA9IHRydWU7XG4gIH1cblxuICByZXR1cm4gcmVxLndyaXRlKGRhdGEsIGVuY29kaW5nKTtcbn07XG5cbi8qKlxuICogUGlwZSB0aGUgcmVxdWVzdCBib2R5IHRvIGBzdHJlYW1gLlxuICpcbiAqIEBwYXJhbSB7U3RyZWFtfSBzdHJlYW1cbiAqIEBwYXJhbSB7T2JqZWN0fSBvcHRpb25zXG4gKiBAcmV0dXJuIHtTdHJlYW19XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnBpcGUgPSBmdW5jdGlvbihzdHJlYW0sIG9wdGlvbnMpIHtcbiAgdGhpcy5waXBlZCA9IHRydWU7IC8vIEhBQ0suLi5cbiAgdGhpcy5idWZmZXIoZmFsc2UpO1xuICB0aGlzLmVuZCgpO1xuICByZXR1cm4gdGhpcy5fcGlwZUNvbnRpbnVlKHN0cmVhbSwgb3B0aW9ucyk7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fcGlwZUNvbnRpbnVlID0gZnVuY3Rpb24oc3RyZWFtLCBvcHRpb25zKSB7XG4gIHRoaXMucmVxLm9uY2UoJ3Jlc3BvbnNlJywgcmVzID0+IHtcbiAgICAvLyByZWRpcmVjdFxuICAgIGlmIChcbiAgICAgIGlzUmVkaXJlY3QocmVzLnN0YXR1c0NvZGUpICYmXG4gICAgICB0aGlzLl9yZWRpcmVjdHMrKyAhPT0gdGhpcy5fbWF4UmVkaXJlY3RzXG4gICAgKSB7XG4gICAgICByZXR1cm4gdGhpcy5fcmVkaXJlY3QocmVzKSA9PT0gdGhpc1xuICAgICAgICA/IHRoaXMuX3BpcGVDb250aW51ZShzdHJlYW0sIG9wdGlvbnMpXG4gICAgICAgIDogdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIHRoaXMucmVzID0gcmVzO1xuICAgIHRoaXMuX2VtaXRSZXNwb25zZSgpO1xuICAgIGlmICh0aGlzLl9hYm9ydGVkKSByZXR1cm47XG5cbiAgICBpZiAodGhpcy5fc2hvdWxkVW56aXAocmVzKSkge1xuICAgICAgY29uc3QgdW56aXBPYmogPSB6bGliLmNyZWF0ZVVuemlwKCk7XG4gICAgICB1bnppcE9iai5vbignZXJyb3InLCBlcnIgPT4ge1xuICAgICAgICBpZiAoZXJyICYmIGVyci5jb2RlID09PSAnWl9CVUZfRVJST1InKSB7XG4gICAgICAgICAgLy8gdW5leHBlY3RlZCBlbmQgb2YgZmlsZSBpcyBpZ25vcmVkIGJ5IGJyb3dzZXJzIGFuZCBjdXJsXG4gICAgICAgICAgc3RyZWFtLmVtaXQoJ2VuZCcpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHN0cmVhbS5lbWl0KCdlcnJvcicsIGVycik7XG4gICAgICB9KTtcbiAgICAgIHJlcy5waXBlKHVuemlwT2JqKS5waXBlKHN0cmVhbSwgb3B0aW9ucyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlcy5waXBlKHN0cmVhbSwgb3B0aW9ucyk7XG4gICAgfVxuXG4gICAgcmVzLm9uY2UoJ2VuZCcsICgpID0+IHtcbiAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgfSk7XG4gIH0pO1xuICByZXR1cm4gc3RyZWFtO1xufTtcblxuLyoqXG4gKiBFbmFibGUgLyBkaXNhYmxlIGJ1ZmZlcmluZy5cbiAqXG4gKiBAcmV0dXJuIHtCb29sZWFufSBbdmFsXVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmJ1ZmZlciA9IGZ1bmN0aW9uKHZhbCkge1xuICB0aGlzLl9idWZmZXIgPSB2YWwgIT09IGZhbHNlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUmVkaXJlY3QgdG8gYHVybFxuICpcbiAqIEBwYXJhbSB7SW5jb21pbmdNZXNzYWdlfSByZXNcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX3JlZGlyZWN0ID0gZnVuY3Rpb24ocmVzKSB7XG4gIGxldCB1cmwgPSByZXMuaGVhZGVycy5sb2NhdGlvbjtcbiAgaWYgKCF1cmwpIHtcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhuZXcgRXJyb3IoJ05vIGxvY2F0aW9uIGhlYWRlciBmb3IgcmVkaXJlY3QnKSwgcmVzKTtcbiAgfVxuXG4gIGRlYnVnKCdyZWRpcmVjdCAlcyAtPiAlcycsIHRoaXMudXJsLCB1cmwpO1xuXG4gIC8vIGxvY2F0aW9uXG4gIHVybCA9IHJlc29sdmUodGhpcy51cmwsIHVybCk7XG5cbiAgLy8gZW5zdXJlIHRoZSByZXNwb25zZSBpcyBiZWluZyBjb25zdW1lZFxuICAvLyB0aGlzIGlzIHJlcXVpcmVkIGZvciBOb2RlIHYwLjEwK1xuICByZXMucmVzdW1lKCk7XG5cbiAgbGV0IGhlYWRlcnMgPSB0aGlzLnJlcS5nZXRIZWFkZXJzID8gdGhpcy5yZXEuZ2V0SGVhZGVycygpIDogdGhpcy5yZXEuX2hlYWRlcnM7XG5cbiAgY29uc3QgY2hhbmdlc09yaWdpbiA9IHBhcnNlKHVybCkuaG9zdCAhPT0gcGFyc2UodGhpcy51cmwpLmhvc3Q7XG5cbiAgLy8gaW1wbGVtZW50YXRpb24gb2YgMzAyIGZvbGxvd2luZyBkZWZhY3RvIHN0YW5kYXJkXG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMzAxIHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDIpIHtcbiAgICAvLyBzdHJpcCBDb250ZW50LSogcmVsYXRlZCBmaWVsZHNcbiAgICAvLyBpbiBjYXNlIG9mIFBPU1QgZXRjXG4gICAgaGVhZGVycyA9IHV0aWxzLmNsZWFuSGVhZGVyKGhlYWRlcnMsIGNoYW5nZXNPcmlnaW4pO1xuXG4gICAgLy8gZm9yY2UgR0VUXG4gICAgdGhpcy5tZXRob2QgPSB0aGlzLm1ldGhvZCA9PT0gJ0hFQUQnID8gJ0hFQUQnIDogJ0dFVCc7XG5cbiAgICAvLyBjbGVhciBkYXRhXG4gICAgdGhpcy5fZGF0YSA9IG51bGw7XG4gIH1cblxuICAvLyAzMDMgaXMgYWx3YXlzIEdFVFxuICBpZiAocmVzLnN0YXR1c0NvZGUgPT09IDMwMykge1xuICAgIC8vIHN0cmlwIENvbnRlbnQtKiByZWxhdGVkIGZpZWxkc1xuICAgIC8vIGluIGNhc2Ugb2YgUE9TVCBldGNcbiAgICBoZWFkZXJzID0gdXRpbHMuY2xlYW5IZWFkZXIoaGVhZGVycywgY2hhbmdlc09yaWdpbik7XG5cbiAgICAvLyBmb3JjZSBtZXRob2RcbiAgICB0aGlzLm1ldGhvZCA9ICdHRVQnO1xuXG4gICAgLy8gY2xlYXIgZGF0YVxuICAgIHRoaXMuX2RhdGEgPSBudWxsO1xuICB9XG5cbiAgLy8gMzA3IHByZXNlcnZlcyBtZXRob2RcbiAgLy8gMzA4IHByZXNlcnZlcyBtZXRob2RcbiAgZGVsZXRlIGhlYWRlcnMuaG9zdDtcblxuICBkZWxldGUgdGhpcy5yZXE7XG4gIGRlbGV0ZSB0aGlzLl9mb3JtRGF0YTtcblxuICAvLyByZW1vdmUgYWxsIGFkZCBoZWFkZXIgZXhjZXB0IFVzZXItQWdlbnRcbiAgX2luaXRIZWFkZXJzKHRoaXMpO1xuXG4gIC8vIHJlZGlyZWN0XG4gIHRoaXMuX2VuZENhbGxlZCA9IGZhbHNlO1xuICB0aGlzLnVybCA9IHVybDtcbiAgdGhpcy5xcyA9IHt9O1xuICB0aGlzLl9xdWVyeS5sZW5ndGggPSAwO1xuICB0aGlzLnNldChoZWFkZXJzKTtcbiAgdGhpcy5lbWl0KCdyZWRpcmVjdCcsIHJlcyk7XG4gIHRoaXMuX3JlZGlyZWN0TGlzdC5wdXNoKHRoaXMudXJsKTtcbiAgdGhpcy5lbmQodGhpcy5fY2FsbGJhY2spO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IEF1dGhvcml6YXRpb24gZmllbGQgdmFsdWUgd2l0aCBgdXNlcmAgYW5kIGBwYXNzYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIC5hdXRoKCd0b2JpJywgJ2xlYXJuYm9vc3QnKVxuICogICAuYXV0aCgndG9iaTpsZWFybmJvb3N0JylcbiAqICAgLmF1dGgoJ3RvYmknKVxuICogICAuYXV0aChhY2Nlc3NUb2tlbiwgeyB0eXBlOiAnYmVhcmVyJyB9KVxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VyXG4gKiBAcGFyYW0ge1N0cmluZ30gW3Bhc3NdXG4gKiBAcGFyYW0ge09iamVjdH0gW29wdGlvbnNdIG9wdGlvbnMgd2l0aCBhdXRob3JpemF0aW9uIHR5cGUgJ2Jhc2ljJyBvciAnYmVhcmVyJyAoJ2Jhc2ljJyBpcyBkZWZhdWx0KVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmF1dGggPSBmdW5jdGlvbih1c2VyLCBwYXNzLCBvcHRpb25zKSB7XG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID09PSAxKSBwYXNzID0gJyc7XG4gIGlmICh0eXBlb2YgcGFzcyA9PT0gJ29iamVjdCcgJiYgcGFzcyAhPT0gbnVsbCkge1xuICAgIC8vIHBhc3MgaXMgb3B0aW9uYWwgYW5kIGNhbiBiZSByZXBsYWNlZCB3aXRoIG9wdGlvbnNcbiAgICBvcHRpb25zID0gcGFzcztcbiAgICBwYXNzID0gJyc7XG4gIH1cblxuICBpZiAoIW9wdGlvbnMpIHtcbiAgICBvcHRpb25zID0geyB0eXBlOiAnYmFzaWMnIH07XG4gIH1cblxuICBjb25zdCBlbmNvZGVyID0gc3RyaW5nID0+IEJ1ZmZlci5mcm9tKHN0cmluZykudG9TdHJpbmcoJ2Jhc2U2NCcpO1xuXG4gIHJldHVybiB0aGlzLl9hdXRoKHVzZXIsIHBhc3MsIG9wdGlvbnMsIGVuY29kZXIpO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGNlcnRpZmljYXRlIGF1dGhvcml0eSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBBcnJheX0gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmNhID0gZnVuY3Rpb24oY2VydCkge1xuICB0aGlzLl9jYSA9IGNlcnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGNsaWVudCBjZXJ0aWZpY2F0ZSBrZXkgb3B0aW9uIGZvciBodHRwcyByZXF1ZXN0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyIHwgU3RyaW5nfSBjZXJ0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUua2V5ID0gZnVuY3Rpb24oY2VydCkge1xuICB0aGlzLl9rZXkgPSBjZXJ0O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IHRoZSBrZXksIGNlcnRpZmljYXRlLCBhbmQgQ0EgY2VydHMgb2YgdGhlIGNsaWVudCBpbiBQRlggb3IgUEtDUzEyIGZvcm1hdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IFN0cmluZ30gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnBmeCA9IGZ1bmN0aW9uKGNlcnQpIHtcbiAgaWYgKHR5cGVvZiBjZXJ0ID09PSAnb2JqZWN0JyAmJiAhQnVmZmVyLmlzQnVmZmVyKGNlcnQpKSB7XG4gICAgdGhpcy5fcGZ4ID0gY2VydC5wZng7XG4gICAgdGhpcy5fcGFzc3BocmFzZSA9IGNlcnQucGFzc3BocmFzZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLl9wZnggPSBjZXJ0O1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgY2xpZW50IGNlcnRpZmljYXRlIG9wdGlvbiBmb3IgaHR0cHMgcmVxdWVzdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IFN0cmluZ30gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmNlcnQgPSBmdW5jdGlvbihjZXJ0KSB7XG4gIHRoaXMuX2NlcnQgPSBjZXJ0O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogRG8gbm90IHJlamVjdCBleHBpcmVkIG9yIGludmFsaWQgVExTIGNlcnRzLlxuICogc2V0cyBgcmVqZWN0VW5hdXRob3JpemVkPXRydWVgLiBCZSB3YXJuZWQgdGhhdCB0aGlzIGFsbG93cyBNSVRNIGF0dGFja3MuXG4gKlxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmRpc2FibGVUTFNDZXJ0cyA9IGZ1bmN0aW9uKCkge1xuICB0aGlzLl9kaXNhYmxlVExTQ2VydHMgPSB0cnVlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUmV0dXJuIGFuIGh0dHBbc10gcmVxdWVzdC5cbiAqXG4gKiBAcmV0dXJuIHtPdXRnb2luZ01lc3NhZ2V9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgY29tcGxleGl0eVxuUmVxdWVzdC5wcm90b3R5cGUucmVxdWVzdCA9IGZ1bmN0aW9uKCkge1xuICBpZiAodGhpcy5yZXEpIHJldHVybiB0aGlzLnJlcTtcblxuICBjb25zdCBvcHRpb25zID0ge307XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBxdWVyeSA9IHFzLnN0cmluZ2lmeSh0aGlzLnFzLCB7XG4gICAgICBpbmRpY2VzOiBmYWxzZSxcbiAgICAgIHN0cmljdE51bGxIYW5kbGluZzogdHJ1ZVxuICAgIH0pO1xuICAgIGlmIChxdWVyeSkge1xuICAgICAgdGhpcy5xcyA9IHt9O1xuICAgICAgdGhpcy5fcXVlcnkucHVzaChxdWVyeSk7XG4gICAgfVxuXG4gICAgdGhpcy5fZmluYWxpemVRdWVyeVN0cmluZygpO1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICByZXR1cm4gdGhpcy5lbWl0KCdlcnJvcicsIGVycik7XG4gIH1cblxuICBsZXQgeyB1cmwgfSA9IHRoaXM7XG4gIGNvbnN0IHJldHJpZXMgPSB0aGlzLl9yZXRyaWVzO1xuXG4gIC8vIENhcHR1cmUgYmFja3RpY2tzIGFzLWlzIGZyb20gdGhlIGZpbmFsIHF1ZXJ5IHN0cmluZyBidWlsdCBhYm92ZS5cbiAgLy8gTm90ZTogdGhpcydsbCBvbmx5IGZpbmQgYmFja3RpY2tzIGVudGVyZWQgaW4gcmVxLnF1ZXJ5KFN0cmluZylcbiAgLy8gY2FsbHMsIGJlY2F1c2UgcXMuc3RyaW5naWZ5IHVuY29uZGl0aW9uYWxseSBlbmNvZGVzIGJhY2t0aWNrcy5cbiAgbGV0IHF1ZXJ5U3RyaW5nQmFja3RpY2tzO1xuICBpZiAodXJsLmluY2x1ZGVzKCdgJykpIHtcbiAgICBjb25zdCBxdWVyeVN0YXJ0SW5kZXggPSB1cmwuaW5kZXhPZignPycpO1xuXG4gICAgaWYgKHF1ZXJ5U3RhcnRJbmRleCAhPT0gLTEpIHtcbiAgICAgIGNvbnN0IHF1ZXJ5U3RyaW5nID0gdXJsLnNsaWNlKHF1ZXJ5U3RhcnRJbmRleCArIDEpO1xuICAgICAgcXVlcnlTdHJpbmdCYWNrdGlja3MgPSBxdWVyeVN0cmluZy5tYXRjaCgvYHwlNjAvZyk7XG4gICAgfVxuICB9XG5cbiAgLy8gZGVmYXVsdCB0byBodHRwOi8vXG4gIGlmICh1cmwuaW5kZXhPZignaHR0cCcpICE9PSAwKSB1cmwgPSBgaHR0cDovLyR7dXJsfWA7XG4gIHVybCA9IHBhcnNlKHVybCk7XG5cbiAgLy8gU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS92aXNpb25tZWRpYS9zdXBlcmFnZW50L2lzc3Vlcy8xMzY3XG4gIGlmIChxdWVyeVN0cmluZ0JhY2t0aWNrcykge1xuICAgIGxldCBpID0gMDtcbiAgICB1cmwucXVlcnkgPSB1cmwucXVlcnkucmVwbGFjZSgvJTYwL2csICgpID0+IHF1ZXJ5U3RyaW5nQmFja3RpY2tzW2krK10pO1xuICAgIHVybC5zZWFyY2ggPSBgPyR7dXJsLnF1ZXJ5fWA7XG4gICAgdXJsLnBhdGggPSB1cmwucGF0aG5hbWUgKyB1cmwuc2VhcmNoO1xuICB9XG5cbiAgLy8gc3VwcG9ydCB1bml4IHNvY2tldHNcbiAgaWYgKC9eaHR0cHM/XFwrdW5peDovLnRlc3QodXJsLnByb3RvY29sKSA9PT0gdHJ1ZSkge1xuICAgIC8vIGdldCB0aGUgcHJvdG9jb2xcbiAgICB1cmwucHJvdG9jb2wgPSBgJHt1cmwucHJvdG9jb2wuc3BsaXQoJysnKVswXX06YDtcblxuICAgIC8vIGdldCB0aGUgc29ja2V0LCBwYXRoXG4gICAgY29uc3QgdW5peFBhcnRzID0gdXJsLnBhdGgubWF0Y2goL14oW14vXSspKC4rKSQvKTtcbiAgICBvcHRpb25zLnNvY2tldFBhdGggPSB1bml4UGFydHNbMV0ucmVwbGFjZSgvJTJGL2csICcvJyk7XG4gICAgdXJsLnBhdGggPSB1bml4UGFydHNbMl07XG4gIH1cblxuICAvLyBPdmVycmlkZSBJUCBhZGRyZXNzIG9mIGEgaG9zdG5hbWVcbiAgaWYgKHRoaXMuX2Nvbm5lY3RPdmVycmlkZSkge1xuICAgIGNvbnN0IHsgaG9zdG5hbWUgfSA9IHVybDtcbiAgICBjb25zdCBtYXRjaCA9XG4gICAgICBob3N0bmFtZSBpbiB0aGlzLl9jb25uZWN0T3ZlcnJpZGVcbiAgICAgICAgPyB0aGlzLl9jb25uZWN0T3ZlcnJpZGVbaG9zdG5hbWVdXG4gICAgICAgIDogdGhpcy5fY29ubmVjdE92ZXJyaWRlWycqJ107XG4gICAgaWYgKG1hdGNoKSB7XG4gICAgICAvLyBiYWNrdXAgdGhlIHJlYWwgaG9zdFxuICAgICAgaWYgKCF0aGlzLl9oZWFkZXIuaG9zdCkge1xuICAgICAgICB0aGlzLnNldCgnaG9zdCcsIHVybC5ob3N0KTtcbiAgICAgIH1cblxuICAgICAgLy8gd3JhcCBbaXB2Nl1cbiAgICAgIHVybC5ob3N0ID0gLzovLnRlc3QobWF0Y2gpID8gYFske21hdGNofV1gIDogbWF0Y2g7XG4gICAgICBpZiAodXJsLnBvcnQpIHtcbiAgICAgICAgdXJsLmhvc3QgKz0gYDoke3VybC5wb3J0fWA7XG4gICAgICB9XG5cbiAgICAgIHVybC5ob3N0bmFtZSA9IG1hdGNoO1xuICAgIH1cbiAgfVxuXG4gIC8vIG9wdGlvbnNcbiAgb3B0aW9ucy5tZXRob2QgPSB0aGlzLm1ldGhvZDtcbiAgb3B0aW9ucy5wb3J0ID0gdXJsLnBvcnQ7XG4gIG9wdGlvbnMucGF0aCA9IHVybC5wYXRoO1xuICBvcHRpb25zLmhvc3QgPSB1cmwuaG9zdG5hbWU7XG4gIG9wdGlvbnMuY2EgPSB0aGlzLl9jYTtcbiAgb3B0aW9ucy5rZXkgPSB0aGlzLl9rZXk7XG4gIG9wdGlvbnMucGZ4ID0gdGhpcy5fcGZ4O1xuICBvcHRpb25zLmNlcnQgPSB0aGlzLl9jZXJ0O1xuICBvcHRpb25zLnBhc3NwaHJhc2UgPSB0aGlzLl9wYXNzcGhyYXNlO1xuICBvcHRpb25zLmFnZW50ID0gdGhpcy5fYWdlbnQ7XG4gIG9wdGlvbnMucmVqZWN0VW5hdXRob3JpemVkID1cbiAgICB0eXBlb2YgdGhpcy5fZGlzYWJsZVRMU0NlcnRzID09PSAnYm9vbGVhbidcbiAgICAgID8gIXRoaXMuX2Rpc2FibGVUTFNDZXJ0c1xuICAgICAgOiBwcm9jZXNzLmVudi5OT0RFX1RMU19SRUpFQ1RfVU5BVVRIT1JJWkVEICE9PSAnMCc7XG5cbiAgLy8gQWxsb3dzIHJlcXVlc3QuZ2V0KCdodHRwczovLzEuMi4zLjQvJykuc2V0KCdIb3N0JywgJ2V4YW1wbGUuY29tJylcbiAgaWYgKHRoaXMuX2hlYWRlci5ob3N0KSB7XG4gICAgb3B0aW9ucy5zZXJ2ZXJuYW1lID0gdGhpcy5faGVhZGVyLmhvc3QucmVwbGFjZSgvOlxcZCskLywgJycpO1xuICB9XG5cbiAgaWYgKFxuICAgIHRoaXMuX3RydXN0TG9jYWxob3N0ICYmXG4gICAgL14oPzpsb2NhbGhvc3R8MTI3XFwuMFxcLjBcXC5cXGQrfCgwKjopKzowKjEpJC8udGVzdCh1cmwuaG9zdG5hbWUpXG4gICkge1xuICAgIG9wdGlvbnMucmVqZWN0VW5hdXRob3JpemVkID0gZmFsc2U7XG4gIH1cblxuICAvLyBpbml0aWF0ZSByZXF1ZXN0XG4gIGNvbnN0IG1vZCA9IHRoaXMuX2VuYWJsZUh0dHAyXG4gICAgPyBleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10uc2V0UHJvdG9jb2wodXJsLnByb3RvY29sKVxuICAgIDogZXhwb3J0cy5wcm90b2NvbHNbdXJsLnByb3RvY29sXTtcblxuICAvLyByZXF1ZXN0XG4gIHRoaXMucmVxID0gbW9kLnJlcXVlc3Qob3B0aW9ucyk7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuXG4gIC8vIHNldCB0Y3Agbm8gZGVsYXlcbiAgcmVxLnNldE5vRGVsYXkodHJ1ZSk7XG5cbiAgaWYgKG9wdGlvbnMubWV0aG9kICE9PSAnSEVBRCcpIHtcbiAgICByZXEuc2V0SGVhZGVyKCdBY2NlcHQtRW5jb2RpbmcnLCAnZ3ppcCwgZGVmbGF0ZScpO1xuICB9XG5cbiAgdGhpcy5wcm90b2NvbCA9IHVybC5wcm90b2NvbDtcbiAgdGhpcy5ob3N0ID0gdXJsLmhvc3Q7XG5cbiAgLy8gZXhwb3NlIGV2ZW50c1xuICByZXEub25jZSgnZHJhaW4nLCAoKSA9PiB7XG4gICAgdGhpcy5lbWl0KCdkcmFpbicpO1xuICB9KTtcblxuICByZXEub24oJ2Vycm9yJywgZXJyID0+IHtcbiAgICAvLyBmbGFnIGFib3J0aW9uIGhlcmUgZm9yIG91dCB0aW1lb3V0c1xuICAgIC8vIGJlY2F1c2Ugbm9kZSB3aWxsIGVtaXQgYSBmYXV4LWVycm9yIFwic29ja2V0IGhhbmcgdXBcIlxuICAgIC8vIHdoZW4gcmVxdWVzdCBpcyBhYm9ydGVkIGJlZm9yZSBhIGNvbm5lY3Rpb24gaXMgbWFkZVxuICAgIGlmICh0aGlzLl9hYm9ydGVkKSByZXR1cm47XG4gICAgLy8gaWYgbm90IHRoZSBzYW1lLCB3ZSBhcmUgaW4gdGhlICoqb2xkKiogKGNhbmNlbGxlZCkgcmVxdWVzdCxcbiAgICAvLyBzbyBuZWVkIHRvIGNvbnRpbnVlIChzYW1lIGFzIGZvciBhYm92ZSlcbiAgICBpZiAodGhpcy5fcmV0cmllcyAhPT0gcmV0cmllcykgcmV0dXJuO1xuICAgIC8vIGlmIHdlJ3ZlIHJlY2VpdmVkIGEgcmVzcG9uc2UgdGhlbiB3ZSBkb24ndCB3YW50IHRvIGxldFxuICAgIC8vIGFuIGVycm9yIGluIHRoZSByZXF1ZXN0IGJsb3cgdXAgdGhlIHJlc3BvbnNlXG4gICAgaWYgKHRoaXMucmVzcG9uc2UpIHJldHVybjtcbiAgICB0aGlzLmNhbGxiYWNrKGVycik7XG4gIH0pO1xuXG4gIC8vIGF1dGhcbiAgaWYgKHVybC5hdXRoKSB7XG4gICAgY29uc3QgYXV0aCA9IHVybC5hdXRoLnNwbGl0KCc6Jyk7XG4gICAgdGhpcy5hdXRoKGF1dGhbMF0sIGF1dGhbMV0pO1xuICB9XG5cbiAgaWYgKHRoaXMudXNlcm5hbWUgJiYgdGhpcy5wYXNzd29yZCkge1xuICAgIHRoaXMuYXV0aCh0aGlzLnVzZXJuYW1lLCB0aGlzLnBhc3N3b3JkKTtcbiAgfVxuXG4gIGZvciAoY29uc3Qga2V5IGluIHRoaXMuaGVhZGVyKSB7XG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbCh0aGlzLmhlYWRlciwga2V5KSlcbiAgICAgIHJlcS5zZXRIZWFkZXIoa2V5LCB0aGlzLmhlYWRlcltrZXldKTtcbiAgfVxuXG4gIC8vIGFkZCBjb29raWVzXG4gIGlmICh0aGlzLmNvb2tpZXMpIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHRoaXMuX2hlYWRlciwgJ2Nvb2tpZScpKSB7XG4gICAgICAvLyBtZXJnZVxuICAgICAgY29uc3QgdG1wSmFyID0gbmV3IENvb2tpZUphci5Db29raWVKYXIoKTtcbiAgICAgIHRtcEphci5zZXRDb29raWVzKHRoaXMuX2hlYWRlci5jb29raWUuc3BsaXQoJzsnKSk7XG4gICAgICB0bXBKYXIuc2V0Q29va2llcyh0aGlzLmNvb2tpZXMuc3BsaXQoJzsnKSk7XG4gICAgICByZXEuc2V0SGVhZGVyKFxuICAgICAgICAnQ29va2llJyxcbiAgICAgICAgdG1wSmFyLmdldENvb2tpZXMoQ29va2llSmFyLkNvb2tpZUFjY2Vzc0luZm8uQWxsKS50b1ZhbHVlU3RyaW5nKClcbiAgICAgICk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlcS5zZXRIZWFkZXIoJ0Nvb2tpZScsIHRoaXMuY29va2llcyk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHJlcTtcbn07XG5cbi8qKlxuICogSW52b2tlIHRoZSBjYWxsYmFjayB3aXRoIGBlcnJgIGFuZCBgcmVzYFxuICogYW5kIGhhbmRsZSBhcml0eSBjaGVjay5cbiAqXG4gKiBAcGFyYW0ge0Vycm9yfSBlcnJcbiAqIEBwYXJhbSB7UmVzcG9uc2V9IHJlc1xuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuY2FsbGJhY2sgPSBmdW5jdGlvbihlcnIsIHJlcykge1xuICBpZiAodGhpcy5fc2hvdWxkUmV0cnkoZXJyLCByZXMpKSB7XG4gICAgcmV0dXJuIHRoaXMuX3JldHJ5KCk7XG4gIH1cblxuICAvLyBBdm9pZCB0aGUgZXJyb3Igd2hpY2ggaXMgZW1pdHRlZCBmcm9tICdzb2NrZXQgaGFuZyB1cCcgdG8gY2F1c2UgdGhlIGZuIHVuZGVmaW5lZCBlcnJvciBvbiBKUyBydW50aW1lLlxuICBjb25zdCBmbiA9IHRoaXMuX2NhbGxiYWNrIHx8IG5vb3A7XG4gIHRoaXMuY2xlYXJUaW1lb3V0KCk7XG4gIGlmICh0aGlzLmNhbGxlZCkgcmV0dXJuIGNvbnNvbGUud2Fybignc3VwZXJhZ2VudDogZG91YmxlIGNhbGxiYWNrIGJ1ZycpO1xuICB0aGlzLmNhbGxlZCA9IHRydWU7XG5cbiAgaWYgKCFlcnIpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCF0aGlzLl9pc1Jlc3BvbnNlT0socmVzKSkge1xuICAgICAgICBsZXQgbXNnID0gJ1Vuc3VjY2Vzc2Z1bCBIVFRQIHJlc3BvbnNlJztcbiAgICAgICAgaWYgKHJlcykge1xuICAgICAgICAgIG1zZyA9IGh0dHAuU1RBVFVTX0NPREVTW3Jlcy5zdGF0dXNdIHx8IG1zZztcbiAgICAgICAgfVxuXG4gICAgICAgIGVyciA9IG5ldyBFcnJvcihtc2cpO1xuICAgICAgICBlcnIuc3RhdHVzID0gcmVzID8gcmVzLnN0YXR1cyA6IHVuZGVmaW5lZDtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJfKSB7XG4gICAgICBlcnIgPSBlcnJfO1xuICAgIH1cbiAgfVxuXG4gIC8vIEl0J3MgaW1wb3J0YW50IHRoYXQgdGhlIGNhbGxiYWNrIGlzIGNhbGxlZCBvdXRzaWRlIHRyeS9jYXRjaFxuICAvLyB0byBhdm9pZCBkb3VibGUgY2FsbGJhY2tcbiAgaWYgKCFlcnIpIHtcbiAgICByZXR1cm4gZm4obnVsbCwgcmVzKTtcbiAgfVxuXG4gIGVyci5yZXNwb25zZSA9IHJlcztcbiAgZXJyLnVybCA9IHRoaXMudXJsO1xuICBpZiAodGhpcy5fbWF4UmV0cmllcykgZXJyLnJldHJpZXMgPSB0aGlzLl9yZXRyaWVzIC0gMTtcblxuICAvLyBvbmx5IGVtaXQgZXJyb3IgZXZlbnQgaWYgdGhlcmUgaXMgYSBsaXN0ZW5lclxuICAvLyBvdGhlcndpc2Ugd2UgYXNzdW1lIHRoZSBjYWxsYmFjayB0byBgLmVuZCgpYCB3aWxsIGdldCB0aGUgZXJyb3JcbiAgaWYgKGVyciAmJiB0aGlzLmxpc3RlbmVycygnZXJyb3InKS5sZW5ndGggPiAwKSB7XG4gICAgdGhpcy5lbWl0KCdlcnJvcicsIGVycik7XG4gIH1cblxuICBmbihlcnIsIHJlcyk7XG59O1xuXG4vKipcbiAqIENoZWNrIGlmIGBvYmpgIGlzIGEgaG9zdCBvYmplY3QsXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IG9iaiBob3N0IG9iamVjdFxuICogQHJldHVybiB7Qm9vbGVhbn0gaXMgYSBob3N0IG9iamVjdFxuICogQGFwaSBwcml2YXRlXG4gKi9cblJlcXVlc3QucHJvdG90eXBlLl9pc0hvc3QgPSBmdW5jdGlvbihvYmopIHtcbiAgcmV0dXJuIChcbiAgICBCdWZmZXIuaXNCdWZmZXIob2JqKSB8fCBvYmogaW5zdGFuY2VvZiBTdHJlYW0gfHwgb2JqIGluc3RhbmNlb2YgRm9ybURhdGFcbiAgKTtcbn07XG5cbi8qKlxuICogSW5pdGlhdGUgcmVxdWVzdCwgaW52b2tpbmcgY2FsbGJhY2sgYGZuKGVyciwgcmVzKWBcbiAqIHdpdGggYW4gaW5zdGFuY2VvZiBgUmVzcG9uc2VgLlxuICpcbiAqIEBwYXJhbSB7RnVuY3Rpb259IGZuXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX2VtaXRSZXNwb25zZSA9IGZ1bmN0aW9uKGJvZHksIGZpbGVzKSB7XG4gIGNvbnN0IHJlc3BvbnNlID0gbmV3IFJlc3BvbnNlKHRoaXMpO1xuICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gIHJlc3BvbnNlLnJlZGlyZWN0cyA9IHRoaXMuX3JlZGlyZWN0TGlzdDtcbiAgaWYgKHVuZGVmaW5lZCAhPT0gYm9keSkge1xuICAgIHJlc3BvbnNlLmJvZHkgPSBib2R5O1xuICB9XG5cbiAgcmVzcG9uc2UuZmlsZXMgPSBmaWxlcztcbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIHJlc3BvbnNlLnBpcGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJlbmQoKSBoYXMgYWxyZWFkeSBiZWVuIGNhbGxlZCwgc28gaXQncyB0b28gbGF0ZSB0byBzdGFydCBwaXBpbmdcIlxuICAgICAgKTtcbiAgICB9O1xuICB9XG5cbiAgdGhpcy5lbWl0KCdyZXNwb25zZScsIHJlc3BvbnNlKTtcbiAgcmV0dXJuIHJlc3BvbnNlO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuZW5kID0gZnVuY3Rpb24oZm4pIHtcbiAgdGhpcy5yZXF1ZXN0KCk7XG4gIGRlYnVnKCclcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG5cbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICcuZW5kKCkgd2FzIGNhbGxlZCB0d2ljZS4gVGhpcyBpcyBub3Qgc3VwcG9ydGVkIGluIHN1cGVyYWdlbnQnXG4gICAgKTtcbiAgfVxuXG4gIHRoaXMuX2VuZENhbGxlZCA9IHRydWU7XG5cbiAgLy8gc3RvcmUgY2FsbGJhY2tcbiAgdGhpcy5fY2FsbGJhY2sgPSBmbiB8fCBub29wO1xuXG4gIHRoaXMuX2VuZCgpO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuX2VuZCA9IGZ1bmN0aW9uKCkge1xuICBpZiAodGhpcy5fYWJvcnRlZClcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhcbiAgICAgIG5ldyBFcnJvcignVGhlIHJlcXVlc3QgaGFzIGJlZW4gYWJvcnRlZCBldmVuIGJlZm9yZSAuZW5kKCkgd2FzIGNhbGxlZCcpXG4gICAgKTtcblxuICBsZXQgZGF0YSA9IHRoaXMuX2RhdGE7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuICBjb25zdCB7IG1ldGhvZCB9ID0gdGhpcztcblxuICB0aGlzLl9zZXRUaW1lb3V0cygpO1xuXG4gIC8vIGJvZHlcbiAgaWYgKG1ldGhvZCAhPT0gJ0hFQUQnICYmICFyZXEuX2hlYWRlclNlbnQpIHtcbiAgICAvLyBzZXJpYWxpemUgc3R1ZmZcbiAgICBpZiAodHlwZW9mIGRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICBsZXQgY29udGVudFR5cGUgPSByZXEuZ2V0SGVhZGVyKCdDb250ZW50LVR5cGUnKTtcbiAgICAgIC8vIFBhcnNlIG91dCBqdXN0IHRoZSBjb250ZW50IHR5cGUgZnJvbSB0aGUgaGVhZGVyIChpZ25vcmUgdGhlIGNoYXJzZXQpXG4gICAgICBpZiAoY29udGVudFR5cGUpIGNvbnRlbnRUeXBlID0gY29udGVudFR5cGUuc3BsaXQoJzsnKVswXTtcbiAgICAgIGxldCBzZXJpYWxpemUgPSB0aGlzLl9zZXJpYWxpemVyIHx8IGV4cG9ydHMuc2VyaWFsaXplW2NvbnRlbnRUeXBlXTtcbiAgICAgIGlmICghc2VyaWFsaXplICYmIGlzSlNPTihjb250ZW50VHlwZSkpIHtcbiAgICAgICAgc2VyaWFsaXplID0gZXhwb3J0cy5zZXJpYWxpemVbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICAgIH1cblxuICAgICAgaWYgKHNlcmlhbGl6ZSkgZGF0YSA9IHNlcmlhbGl6ZShkYXRhKTtcbiAgICB9XG5cbiAgICAvLyBjb250ZW50LWxlbmd0aFxuICAgIGlmIChkYXRhICYmICFyZXEuZ2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcpKSB7XG4gICAgICByZXEuc2V0SGVhZGVyKFxuICAgICAgICAnQ29udGVudC1MZW5ndGgnLFxuICAgICAgICBCdWZmZXIuaXNCdWZmZXIoZGF0YSkgPyBkYXRhLmxlbmd0aCA6IEJ1ZmZlci5ieXRlTGVuZ3RoKGRhdGEpXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8vIHJlc3BvbnNlXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG4gIHJlcS5vbmNlKCdyZXNwb25zZScsIHJlcyA9PiB7XG4gICAgZGVidWcoJyVzICVzIC0+ICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsLCByZXMuc3RhdHVzQ29kZSk7XG5cbiAgICBpZiAodGhpcy5fcmVzcG9uc2VUaW1lb3V0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLl9yZXNwb25zZVRpbWVvdXRUaW1lcik7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMucGlwZWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBtYXggPSB0aGlzLl9tYXhSZWRpcmVjdHM7XG4gICAgY29uc3QgbWltZSA9IHV0aWxzLnR5cGUocmVzLmhlYWRlcnNbJ2NvbnRlbnQtdHlwZSddIHx8ICcnKSB8fCAndGV4dC9wbGFpbic7XG4gICAgY29uc3QgdHlwZSA9IG1pbWUuc3BsaXQoJy8nKVswXTtcbiAgICBjb25zdCBtdWx0aXBhcnQgPSB0eXBlID09PSAnbXVsdGlwYXJ0JztcbiAgICBjb25zdCByZWRpcmVjdCA9IGlzUmVkaXJlY3QocmVzLnN0YXR1c0NvZGUpO1xuICAgIGNvbnN0IHJlc3BvbnNlVHlwZSA9IHRoaXMuX3Jlc3BvbnNlVHlwZTtcblxuICAgIHRoaXMucmVzID0gcmVzO1xuXG4gICAgLy8gcmVkaXJlY3RcbiAgICBpZiAocmVkaXJlY3QgJiYgdGhpcy5fcmVkaXJlY3RzKysgIT09IG1heCkge1xuICAgICAgcmV0dXJuIHRoaXMuX3JlZGlyZWN0KHJlcyk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMubWV0aG9kID09PSAnSEVBRCcpIHtcbiAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgICB0aGlzLmNhbGxiYWNrKG51bGwsIHRoaXMuX2VtaXRSZXNwb25zZSgpKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyB6bGliIHN1cHBvcnRcbiAgICBpZiAodGhpcy5fc2hvdWxkVW56aXAocmVzKSkge1xuICAgICAgdW56aXAocmVxLCByZXMpO1xuICAgIH1cblxuICAgIGxldCBidWZmZXIgPSB0aGlzLl9idWZmZXI7XG4gICAgaWYgKGJ1ZmZlciA9PT0gdW5kZWZpbmVkICYmIG1pbWUgaW4gZXhwb3J0cy5idWZmZXIpIHtcbiAgICAgIGJ1ZmZlciA9IEJvb2xlYW4oZXhwb3J0cy5idWZmZXJbbWltZV0pO1xuICAgIH1cblxuICAgIGxldCBwYXJzZXIgPSB0aGlzLl9wYXJzZXI7XG4gICAgaWYgKHVuZGVmaW5lZCA9PT0gYnVmZmVyKSB7XG4gICAgICBpZiAocGFyc2VyKSB7XG4gICAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgICBcIkEgY3VzdG9tIHN1cGVyYWdlbnQgcGFyc2VyIGhhcyBiZWVuIHNldCwgYnV0IGJ1ZmZlcmluZyBzdHJhdGVneSBmb3IgdGhlIHBhcnNlciBoYXNuJ3QgYmVlbiBjb25maWd1cmVkLiBDYWxsIGByZXEuYnVmZmVyKHRydWUgb3IgZmFsc2UpYCBvciBzZXQgYHN1cGVyYWdlbnQuYnVmZmVyW21pbWVdID0gdHJ1ZSBvciBmYWxzZWBcIlxuICAgICAgICApO1xuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmICghcGFyc2VyKSB7XG4gICAgICBpZiAocmVzcG9uc2VUeXBlKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7IC8vIEl0J3MgYWN0dWFsbHkgYSBnZW5lcmljIEJ1ZmZlclxuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfSBlbHNlIGlmIChtdWx0aXBhcnQpIHtcbiAgICAgICAgY29uc3QgZm9ybSA9IG5ldyBmb3JtaWRhYmxlLkluY29taW5nRm9ybSgpO1xuICAgICAgICBwYXJzZXIgPSBmb3JtLnBhcnNlLmJpbmQoZm9ybSk7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9IGVsc2UgaWYgKGlzSW1hZ2VPclZpZGVvKG1pbWUpKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7IC8vIEZvciBiYWNrd2FyZHMtY29tcGF0aWJpbGl0eSBidWZmZXJpbmcgZGVmYXVsdCBpcyBhZC1ob2MgTUlNRS1kZXBlbmRlbnRcbiAgICAgIH0gZWxzZSBpZiAoZXhwb3J0cy5wYXJzZVttaW1lXSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlW21pbWVdO1xuICAgICAgfSBlbHNlIGlmICh0eXBlID09PSAndGV4dCcpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS50ZXh0O1xuICAgICAgICBidWZmZXIgPSBidWZmZXIgIT09IGZhbHNlO1xuXG4gICAgICAgIC8vIGV2ZXJ5b25lIHdhbnRzIHRoZWlyIG93biB3aGl0ZS1sYWJlbGVkIGpzb25cbiAgICAgIH0gZWxzZSBpZiAoaXNKU09OKG1pbWUpKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2VbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICAgICAgYnVmZmVyID0gYnVmZmVyICE9PSBmYWxzZTtcbiAgICAgIH0gZWxzZSBpZiAoYnVmZmVyKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UudGV4dDtcbiAgICAgIH0gZWxzZSBpZiAodW5kZWZpbmVkID09PSBidWZmZXIpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS5pbWFnZTsgLy8gSXQncyBhY3R1YWxseSBhIGdlbmVyaWMgQnVmZmVyXG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gYnkgZGVmYXVsdCBvbmx5IGJ1ZmZlciB0ZXh0LyosIGpzb24gYW5kIG1lc3NlZCB1cCB0aGluZyBmcm9tIGhlbGxcbiAgICBpZiAoKHVuZGVmaW5lZCA9PT0gYnVmZmVyICYmIGlzVGV4dChtaW1lKSkgfHwgaXNKU09OKG1pbWUpKSB7XG4gICAgICBidWZmZXIgPSB0cnVlO1xuICAgIH1cblxuICAgIHRoaXMuX3Jlc0J1ZmZlcmVkID0gYnVmZmVyO1xuICAgIGxldCBwYXJzZXJIYW5kbGVzRW5kID0gZmFsc2U7XG4gICAgaWYgKGJ1ZmZlcikge1xuICAgICAgLy8gUHJvdGVjdGlvbmEgYWdhaW5zdCB6aXAgYm9tYnMgYW5kIG90aGVyIG51aXNhbmNlXG4gICAgICBsZXQgcmVzcG9uc2VCeXRlc0xlZnQgPSB0aGlzLl9tYXhSZXNwb25zZVNpemUgfHwgMjAwMDAwMDAwO1xuICAgICAgcmVzLm9uKCdkYXRhJywgYnVmID0+IHtcbiAgICAgICAgcmVzcG9uc2VCeXRlc0xlZnQgLT0gYnVmLmJ5dGVMZW5ndGggfHwgYnVmLmxlbmd0aDtcbiAgICAgICAgaWYgKHJlc3BvbnNlQnl0ZXNMZWZ0IDwgMCkge1xuICAgICAgICAgIC8vIFRoaXMgd2lsbCBwcm9wYWdhdGUgdGhyb3VnaCBlcnJvciBldmVudFxuICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBFcnJvcignTWF4aW11bSByZXNwb25zZSBzaXplIHJlYWNoZWQnKTtcbiAgICAgICAgICBlcnIuY29kZSA9ICdFVE9PTEFSR0UnO1xuICAgICAgICAgIC8vIFBhcnNlcnMgYXJlbid0IHJlcXVpcmVkIHRvIG9ic2VydmUgZXJyb3IgZXZlbnQsXG4gICAgICAgICAgLy8gc28gd291bGQgaW5jb3JyZWN0bHkgcmVwb3J0IHN1Y2Nlc3NcbiAgICAgICAgICBwYXJzZXJIYW5kbGVzRW5kID0gZmFsc2U7XG4gICAgICAgICAgLy8gV2lsbCBlbWl0IGVycm9yIGV2ZW50XG4gICAgICAgICAgcmVzLmRlc3Ryb3koZXJyKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgaWYgKHBhcnNlcikge1xuICAgICAgdHJ5IHtcbiAgICAgICAgLy8gVW5idWZmZXJlZCBwYXJzZXJzIGFyZSBzdXBwb3NlZCB0byBlbWl0IHJlc3BvbnNlIGVhcmx5LFxuICAgICAgICAvLyB3aGljaCBpcyB3ZWlyZCBCVFcsIGJlY2F1c2UgcmVzcG9uc2UuYm9keSB3b24ndCBiZSB0aGVyZS5cbiAgICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGJ1ZmZlcjtcblxuICAgICAgICBwYXJzZXIocmVzLCAoZXJyLCBvYmosIGZpbGVzKSA9PiB7XG4gICAgICAgICAgaWYgKHRoaXMudGltZWRvdXQpIHtcbiAgICAgICAgICAgIC8vIFRpbWVvdXQgaGFzIGFscmVhZHkgaGFuZGxlZCBhbGwgY2FsbGJhY2tzXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gSW50ZW50aW9uYWwgKG5vbi10aW1lb3V0KSBhYm9ydCBpcyBzdXBwb3NlZCB0byBwcmVzZXJ2ZSBwYXJ0aWFsIHJlc3BvbnNlLFxuICAgICAgICAgIC8vIGV2ZW4gaWYgaXQgZG9lc24ndCBwYXJzZS5cbiAgICAgICAgICBpZiAoZXJyICYmICF0aGlzLl9hYm9ydGVkKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChwYXJzZXJIYW5kbGVzRW5kKSB7XG4gICAgICAgICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2Uob2JqLCBmaWxlcykpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG5cbiAgICAvLyB1bmJ1ZmZlcmVkXG4gICAgaWYgKCFidWZmZXIpIHtcbiAgICAgIGRlYnVnKCd1bmJ1ZmZlcmVkICVzICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsKTtcbiAgICAgIHRoaXMuY2FsbGJhY2sobnVsbCwgdGhpcy5fZW1pdFJlc3BvbnNlKCkpO1xuICAgICAgaWYgKG11bHRpcGFydCkgcmV0dXJuOyAvLyBhbGxvdyBtdWx0aXBhcnQgdG8gaGFuZGxlIGVuZCBldmVudFxuICAgICAgcmVzLm9uY2UoJ2VuZCcsICgpID0+IHtcbiAgICAgICAgZGVidWcoJ2VuZCAlcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG4gICAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyB0ZXJtaW5hdGluZyBldmVudHNcbiAgICByZXMub25jZSgnZXJyb3InLCBlcnIgPT4ge1xuICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgICAgdGhpcy5jYWxsYmFjayhlcnIsIG51bGwpO1xuICAgIH0pO1xuICAgIGlmICghcGFyc2VySGFuZGxlc0VuZClcbiAgICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgIGRlYnVnKCdlbmQgJXMgJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwpO1xuICAgICAgICAvLyBUT0RPOiB1bmxlc3MgYnVmZmVyaW5nIGVtaXQgZWFybGllciB0byBzdHJlYW1cbiAgICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2UoKSk7XG4gICAgICB9KTtcbiAgfSk7XG5cbiAgdGhpcy5lbWl0KCdyZXF1ZXN0JywgdGhpcyk7XG5cbiAgY29uc3QgZ2V0UHJvZ3Jlc3NNb25pdG9yID0gKCkgPT4ge1xuICAgIGNvbnN0IGxlbmd0aENvbXB1dGFibGUgPSB0cnVlO1xuICAgIGNvbnN0IHRvdGFsID0gcmVxLmdldEhlYWRlcignQ29udGVudC1MZW5ndGgnKTtcbiAgICBsZXQgbG9hZGVkID0gMDtcblxuICAgIGNvbnN0IHByb2dyZXNzID0gbmV3IFN0cmVhbS5UcmFuc2Zvcm0oKTtcbiAgICBwcm9ncmVzcy5fdHJhbnNmb3JtID0gKGNodW5rLCBlbmNvZGluZywgY2IpID0+IHtcbiAgICAgIGxvYWRlZCArPSBjaHVuay5sZW5ndGg7XG4gICAgICB0aGlzLmVtaXQoJ3Byb2dyZXNzJywge1xuICAgICAgICBkaXJlY3Rpb246ICd1cGxvYWQnLFxuICAgICAgICBsZW5ndGhDb21wdXRhYmxlLFxuICAgICAgICBsb2FkZWQsXG4gICAgICAgIHRvdGFsXG4gICAgICB9KTtcbiAgICAgIGNiKG51bGwsIGNodW5rKTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHByb2dyZXNzO1xuICB9O1xuXG4gIGNvbnN0IGJ1ZmZlclRvQ2h1bmtzID0gYnVmZmVyID0+IHtcbiAgICBjb25zdCBjaHVua1NpemUgPSAxNiAqIDEwMjQ7IC8vIGRlZmF1bHQgaGlnaFdhdGVyTWFyayB2YWx1ZVxuICAgIGNvbnN0IGNodW5raW5nID0gbmV3IFN0cmVhbS5SZWFkYWJsZSgpO1xuICAgIGNvbnN0IHRvdGFsTGVuZ3RoID0gYnVmZmVyLmxlbmd0aDtcbiAgICBjb25zdCByZW1haW5kZXIgPSB0b3RhbExlbmd0aCAlIGNodW5rU2l6ZTtcbiAgICBjb25zdCBjdXRvZmYgPSB0b3RhbExlbmd0aCAtIHJlbWFpbmRlcjtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY3V0b2ZmOyBpICs9IGNodW5rU2l6ZSkge1xuICAgICAgY29uc3QgY2h1bmsgPSBidWZmZXIuc2xpY2UoaSwgaSArIGNodW5rU2l6ZSk7XG4gICAgICBjaHVua2luZy5wdXNoKGNodW5rKTtcbiAgICB9XG5cbiAgICBpZiAocmVtYWluZGVyID4gMCkge1xuICAgICAgY29uc3QgcmVtYWluZGVyQnVmZmVyID0gYnVmZmVyLnNsaWNlKC1yZW1haW5kZXIpO1xuICAgICAgY2h1bmtpbmcucHVzaChyZW1haW5kZXJCdWZmZXIpO1xuICAgIH1cblxuICAgIGNodW5raW5nLnB1c2gobnVsbCk7IC8vIG5vIG1vcmUgZGF0YVxuXG4gICAgcmV0dXJuIGNodW5raW5nO1xuICB9O1xuXG4gIC8vIGlmIGEgRm9ybURhdGEgaW5zdGFuY2UgZ290IGNyZWF0ZWQsIHRoZW4gd2Ugc2VuZCB0aGF0IGFzIHRoZSByZXF1ZXN0IGJvZHlcbiAgY29uc3QgZm9ybURhdGEgPSB0aGlzLl9mb3JtRGF0YTtcbiAgaWYgKGZvcm1EYXRhKSB7XG4gICAgLy8gc2V0IGhlYWRlcnNcbiAgICBjb25zdCBoZWFkZXJzID0gZm9ybURhdGEuZ2V0SGVhZGVycygpO1xuICAgIGZvciAoY29uc3QgaSBpbiBoZWFkZXJzKSB7XG4gICAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKGhlYWRlcnMsIGkpKSB7XG4gICAgICAgIGRlYnVnKCdzZXR0aW5nIEZvcm1EYXRhIGhlYWRlcjogXCIlczogJXNcIicsIGksIGhlYWRlcnNbaV0pO1xuICAgICAgICByZXEuc2V0SGVhZGVyKGksIGhlYWRlcnNbaV0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIGF0dGVtcHQgdG8gZ2V0IFwiQ29udGVudC1MZW5ndGhcIiBoZWFkZXJcbiAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgaGFuZGxlLWNhbGxiYWNrLWVyclxuICAgIGZvcm1EYXRhLmdldExlbmd0aCgoZXJyLCBsZW5ndGgpID0+IHtcbiAgICAgIC8vIFRPRE86IEFkZCBjaHVua2VkIGVuY29kaW5nIHdoZW4gbm8gbGVuZ3RoIChpZiBlcnIpXG5cbiAgICAgIGRlYnVnKCdnb3QgRm9ybURhdGEgQ29udGVudC1MZW5ndGg6ICVzJywgbGVuZ3RoKTtcbiAgICAgIGlmICh0eXBlb2YgbGVuZ3RoID09PSAnbnVtYmVyJykge1xuICAgICAgICByZXEuc2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcsIGxlbmd0aCk7XG4gICAgICB9XG5cbiAgICAgIGZvcm1EYXRhLnBpcGUoZ2V0UHJvZ3Jlc3NNb25pdG9yKCkpLnBpcGUocmVxKTtcbiAgICB9KTtcbiAgfSBlbHNlIGlmIChCdWZmZXIuaXNCdWZmZXIoZGF0YSkpIHtcbiAgICBidWZmZXJUb0NodW5rcyhkYXRhKVxuICAgICAgLnBpcGUoZ2V0UHJvZ3Jlc3NNb25pdG9yKCkpXG4gICAgICAucGlwZShyZXEpO1xuICB9IGVsc2Uge1xuICAgIHJlcS5lbmQoZGF0YSk7XG4gIH1cbn07XG5cbi8vIENoZWNrIHdoZXRoZXIgcmVzcG9uc2UgaGFzIGEgbm9uLTAtc2l6ZWQgZ3ppcC1lbmNvZGVkIGJvZHlcblJlcXVlc3QucHJvdG90eXBlLl9zaG91bGRVbnppcCA9IHJlcyA9PiB7XG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMjA0IHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDQpIHtcbiAgICAvLyBUaGVzZSBhcmVuJ3Qgc3VwcG9zZWQgdG8gaGF2ZSBhbnkgYm9keVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8vIGhlYWRlciBjb250ZW50IGlzIGEgc3RyaW5nLCBhbmQgZGlzdGluY3Rpb24gYmV0d2VlbiAwIGFuZCBubyBpbmZvcm1hdGlvbiBpcyBjcnVjaWFsXG4gIGlmIChyZXMuaGVhZGVyc1snY29udGVudC1sZW5ndGgnXSA9PT0gJzAnKSB7XG4gICAgLy8gV2Uga25vdyB0aGF0IHRoZSBib2R5IGlzIGVtcHR5ICh1bmZvcnR1bmF0ZWx5LCB0aGlzIGNoZWNrIGRvZXMgbm90IGNvdmVyIGNodW5rZWQgZW5jb2RpbmcpXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLy8gY29uc29sZS5sb2cocmVzKTtcbiAgcmV0dXJuIC9eXFxzKig/OmRlZmxhdGV8Z3ppcClcXHMqJC8udGVzdChyZXMuaGVhZGVyc1snY29udGVudC1lbmNvZGluZyddKTtcbn07XG5cbi8qKlxuICogT3ZlcnJpZGVzIEROUyBmb3Igc2VsZWN0ZWQgaG9zdG5hbWVzLiBUYWtlcyBvYmplY3QgbWFwcGluZyBob3N0bmFtZXMgdG8gSVAgYWRkcmVzc2VzLlxuICpcbiAqIFdoZW4gbWFraW5nIGEgcmVxdWVzdCB0byBhIFVSTCB3aXRoIGEgaG9zdG5hbWUgZXhhY3RseSBtYXRjaGluZyBhIGtleSBpbiB0aGUgb2JqZWN0LFxuICogdXNlIHRoZSBnaXZlbiBJUCBhZGRyZXNzIHRvIGNvbm5lY3QsIGluc3RlYWQgb2YgdXNpbmcgRE5TIHRvIHJlc29sdmUgdGhlIGhvc3RuYW1lLlxuICpcbiAqIEEgc3BlY2lhbCBob3N0IGAqYCBtYXRjaGVzIGV2ZXJ5IGhvc3RuYW1lIChrZWVwIHJlZGlyZWN0cyBpbiBtaW5kISlcbiAqXG4gKiAgICAgIHJlcXVlc3QuY29ubmVjdCh7XG4gKiAgICAgICAgJ3Rlc3QuZXhhbXBsZS5jb20nOiAnMTI3LjAuMC4xJyxcbiAqICAgICAgICAnaXB2Ni5leGFtcGxlLmNvbSc6ICc6OjEnLFxuICogICAgICB9KVxuICovXG5SZXF1ZXN0LnByb3RvdHlwZS5jb25uZWN0ID0gZnVuY3Rpb24oY29ubmVjdE92ZXJyaWRlKSB7XG4gIGlmICh0eXBlb2YgY29ubmVjdE92ZXJyaWRlID09PSAnc3RyaW5nJykge1xuICAgIHRoaXMuX2Nvbm5lY3RPdmVycmlkZSA9IHsgJyonOiBjb25uZWN0T3ZlcnJpZGUgfTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgY29ubmVjdE92ZXJyaWRlID09PSAnb2JqZWN0Jykge1xuICAgIHRoaXMuX2Nvbm5lY3RPdmVycmlkZSA9IGNvbm5lY3RPdmVycmlkZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSB1bmRlZmluZWQ7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnRydXN0TG9jYWxob3N0ID0gZnVuY3Rpb24odG9nZ2xlKSB7XG4gIHRoaXMuX3RydXN0TG9jYWxob3N0ID0gdG9nZ2xlID09PSB1bmRlZmluZWQgPyB0cnVlIDogdG9nZ2xlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8vIGdlbmVyYXRlIEhUVFAgdmVyYiBtZXRob2RzXG5pZiAoIW1ldGhvZHMuaW5jbHVkZXMoJ2RlbCcpKSB7XG4gIC8vIGNyZWF0ZSBhIGNvcHkgc28gd2UgZG9uJ3QgY2F1c2UgY29uZmxpY3RzIHdpdGhcbiAgLy8gb3RoZXIgcGFja2FnZXMgdXNpbmcgdGhlIG1ldGhvZHMgcGFja2FnZSBhbmRcbiAgLy8gbnBtIDMueFxuICBtZXRob2RzID0gbWV0aG9kcy5zbGljZSgwKTtcbiAgbWV0aG9kcy5wdXNoKCdkZWwnKTtcbn1cblxubWV0aG9kcy5mb3JFYWNoKG1ldGhvZCA9PiB7XG4gIGNvbnN0IG5hbWUgPSBtZXRob2Q7XG4gIG1ldGhvZCA9IG1ldGhvZCA9PT0gJ2RlbCcgPyAnZGVsZXRlJyA6IG1ldGhvZDtcblxuICBtZXRob2QgPSBtZXRob2QudG9VcHBlckNhc2UoKTtcbiAgcmVxdWVzdFtuYW1lXSA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gICAgY29uc3QgcmVxID0gcmVxdWVzdChtZXRob2QsIHVybCk7XG4gICAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBmbiA9IGRhdGE7XG4gICAgICBkYXRhID0gbnVsbDtcbiAgICB9XG5cbiAgICBpZiAoZGF0YSkge1xuICAgICAgaWYgKG1ldGhvZCA9PT0gJ0dFVCcgfHwgbWV0aG9kID09PSAnSEVBRCcpIHtcbiAgICAgICAgcmVxLnF1ZXJ5KGRhdGEpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmVxLnNlbmQoZGF0YSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGZuKSByZXEuZW5kKGZuKTtcbiAgICByZXR1cm4gcmVxO1xuICB9O1xufSk7XG5cbi8qKlxuICogQ2hlY2sgaWYgYG1pbWVgIGlzIHRleHQgYW5kIHNob3VsZCBiZSBidWZmZXJlZC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gbWltZVxuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gaXNUZXh0KG1pbWUpIHtcbiAgY29uc3QgcGFydHMgPSBtaW1lLnNwbGl0KCcvJyk7XG4gIGNvbnN0IHR5cGUgPSBwYXJ0c1swXTtcbiAgY29uc3Qgc3VidHlwZSA9IHBhcnRzWzFdO1xuXG4gIHJldHVybiB0eXBlID09PSAndGV4dCcgfHwgc3VidHlwZSA9PT0gJ3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc7XG59XG5cbmZ1bmN0aW9uIGlzSW1hZ2VPclZpZGVvKG1pbWUpIHtcbiAgY29uc3QgdHlwZSA9IG1pbWUuc3BsaXQoJy8nKVswXTtcblxuICByZXR1cm4gdHlwZSA9PT0gJ2ltYWdlJyB8fCB0eXBlID09PSAndmlkZW8nO1xufVxuXG4vKipcbiAqIENoZWNrIGlmIGBtaW1lYCBpcyBqc29uIG9yIGhhcyAranNvbiBzdHJ1Y3R1cmVkIHN5bnRheCBzdWZmaXguXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1pbWVcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBpc0pTT04obWltZSkge1xuICAvLyBzaG91bGQgbWF0Y2ggL2pzb24gb3IgK2pzb25cbiAgLy8gYnV0IG5vdCAvanNvbi1zZXFcbiAgcmV0dXJuIC9bLytdanNvbigkfFteLVxcd10pLy50ZXN0KG1pbWUpO1xufVxuXG4vKipcbiAqIENoZWNrIGlmIHdlIHNob3VsZCBmb2xsb3cgdGhlIHJlZGlyZWN0IGBjb2RlYC5cbiAqXG4gKiBAcGFyYW0ge051bWJlcn0gY29kZVxuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIGlzUmVkaXJlY3QoY29kZSkge1xuICByZXR1cm4gWzMwMSwgMzAyLCAzMDMsIDMwNSwgMzA3LCAzMDhdLmluY2x1ZGVzKGNvZGUpO1xufVxuIl19