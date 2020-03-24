"use strict";

function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Root reference for iframes.
 */
var root;

if (typeof window !== 'undefined') {
  // Browser window
  root = window;
} else if (typeof self === 'undefined') {
  // Other environments
  console.warn('Using browser-only version of superagent in non-browser environment');
  root = void 0;
} else {
  // Web Worker
  root = self;
}

var Emitter = require('component-emitter');

var safeStringify = require('fast-safe-stringify');

var RequestBase = require('./request-base');

var isObject = require('./is-object');

var ResponseBase = require('./response-base');

var Agent = require('./agent-base');
/**
 * Noop.
 */


function noop() {}
/**
 * Expose `request`.
 */


module.exports = function (method, url) {
  // callback
  if (typeof url === 'function') {
    return new exports.Request('GET', method).end(url);
  } // url first


  if (arguments.length === 1) {
    return new exports.Request('GET', method);
  }

  return new exports.Request(method, url);
};

exports = module.exports;
var request = exports;
exports.Request = Request;
/**
 * Determine XHR.
 */

request.getXHR = function () {
  if (root.XMLHttpRequest && (!root.location || root.location.protocol !== 'file:' || !root.ActiveXObject)) {
    return new XMLHttpRequest();
  }

  try {
    return new ActiveXObject('Microsoft.XMLHTTP');
  } catch (_unused) {}

  try {
    return new ActiveXObject('Msxml2.XMLHTTP.6.0');
  } catch (_unused2) {}

  try {
    return new ActiveXObject('Msxml2.XMLHTTP.3.0');
  } catch (_unused3) {}

  try {
    return new ActiveXObject('Msxml2.XMLHTTP');
  } catch (_unused4) {}

  throw new Error('Browser-only version of superagent could not find XHR');
};
/**
 * Removes leading and trailing whitespace, added to support IE.
 *
 * @param {String} s
 * @return {String}
 * @api private
 */


var trim = ''.trim ? function (s) {
  return s.trim();
} : function (s) {
  return s.replace(/(^\s*|\s*$)/g, '');
};
/**
 * Serialize the given `obj`.
 *
 * @param {Object} obj
 * @return {String}
 * @api private
 */

function serialize(obj) {
  if (!isObject(obj)) return obj;
  var pairs = [];

  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) pushEncodedKeyValuePair(pairs, key, obj[key]);
  }

  return pairs.join('&');
}
/**
 * Helps 'serialize' with serializing arrays.
 * Mutates the pairs array.
 *
 * @param {Array} pairs
 * @param {String} key
 * @param {Mixed} val
 */


function pushEncodedKeyValuePair(pairs, key, val) {
  if (val === undefined) return;

  if (val === null) {
    pairs.push(encodeURI(key));
    return;
  }

  if (Array.isArray(val)) {
    val.forEach(function (v) {
      pushEncodedKeyValuePair(pairs, key, v);
    });
  } else if (isObject(val)) {
    for (var subkey in val) {
      if (Object.prototype.hasOwnProperty.call(val, subkey)) pushEncodedKeyValuePair(pairs, "".concat(key, "[").concat(subkey, "]"), val[subkey]);
    }
  } else {
    pairs.push(encodeURI(key) + '=' + encodeURIComponent(val));
  }
}
/**
 * Expose serialization method.
 */


request.serializeObject = serialize;
/**
 * Parse the given x-www-form-urlencoded `str`.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */

function parseString(str) {
  var obj = {};
  var pairs = str.split('&');
  var pair;
  var pos;

  for (var i = 0, len = pairs.length; i < len; ++i) {
    pair = pairs[i];
    pos = pair.indexOf('=');

    if (pos === -1) {
      obj[decodeURIComponent(pair)] = '';
    } else {
      obj[decodeURIComponent(pair.slice(0, pos))] = decodeURIComponent(pair.slice(pos + 1));
    }
  }

  return obj;
}
/**
 * Expose parser.
 */


request.parseString = parseString;
/**
 * Default MIME type map.
 *
 *     superagent.types.xml = 'application/xml';
 *
 */

request.types = {
  html: 'text/html',
  json: 'application/json',
  xml: 'text/xml',
  urlencoded: 'application/x-www-form-urlencoded',
  form: 'application/x-www-form-urlencoded',
  'form-data': 'application/x-www-form-urlencoded'
};
/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

request.serialize = {
  'application/x-www-form-urlencoded': serialize,
  'application/json': safeStringify
};
/**
 * Default parsers.
 *
 *     superagent.parse['application/xml'] = function(str){
 *       return { object parsed from str };
 *     };
 *
 */

request.parse = {
  'application/x-www-form-urlencoded': parseString,
  'application/json': JSON.parse
};
/**
 * Parse the given header `str` into
 * an object containing the mapped fields.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */

function parseHeader(str) {
  var lines = str.split(/\r?\n/);
  var fields = {};
  var index;
  var line;
  var field;
  var val;

  for (var i = 0, len = lines.length; i < len; ++i) {
    line = lines[i];
    index = line.indexOf(':');

    if (index === -1) {
      // could be empty line, just skip it
      continue;
    }

    field = line.slice(0, index).toLowerCase();
    val = trim(line.slice(index + 1));
    fields[field] = val;
  }

  return fields;
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
 * Initialize a new `Response` with the given `xhr`.
 *
 *  - set flags (.ok, .error, etc)
 *  - parse header
 *
 * Examples:
 *
 *  Aliasing `superagent` as `request` is nice:
 *
 *      request = superagent;
 *
 *  We can use the promise-like API, or pass callbacks:
 *
 *      request.get('/').end(function(res){});
 *      request.get('/', function(res){});
 *
 *  Sending data can be chained:
 *
 *      request
 *        .post('/user')
 *        .send({ name: 'tj' })
 *        .end(function(res){});
 *
 *  Or passed to `.send()`:
 *
 *      request
 *        .post('/user')
 *        .send({ name: 'tj' }, function(res){});
 *
 *  Or passed to `.post()`:
 *
 *      request
 *        .post('/user', { name: 'tj' })
 *        .end(function(res){});
 *
 * Or further reduced to a single call for simple cases:
 *
 *      request
 *        .post('/user', { name: 'tj' }, function(res){});
 *
 * @param {XMLHTTPRequest} xhr
 * @param {Object} options
 * @api private
 */


function Response(req) {
  this.req = req;
  this.xhr = this.req.xhr; // responseText is accessible only if responseType is '' or 'text' and on older browsers

  this.text = this.req.method !== 'HEAD' && (this.xhr.responseType === '' || this.xhr.responseType === 'text') || typeof this.xhr.responseType === 'undefined' ? this.xhr.responseText : null;
  this.statusText = this.req.xhr.statusText;
  var status = this.xhr.status; // handle IE9 bug: http://stackoverflow.com/questions/10046972/msie-returns-status-code-of-1223-for-ajax-request

  if (status === 1223) {
    status = 204;
  }

  this._setStatusProperties(status);

  this.headers = parseHeader(this.xhr.getAllResponseHeaders());
  this.header = this.headers; // getAllResponseHeaders sometimes falsely returns "" for CORS requests, but
  // getResponseHeader still works. so we get content-type even if getting
  // other headers fails.

  this.header['content-type'] = this.xhr.getResponseHeader('content-type');

  this._setHeaderProperties(this.header);

  if (this.text === null && req._responseType) {
    this.body = this.xhr.response;
  } else {
    this.body = this.req.method === 'HEAD' ? null : this._parseBody(this.text ? this.text : this.xhr.response);
  }
} // eslint-disable-next-line new-cap


ResponseBase(Response.prototype);
/**
 * Parse the given body `str`.
 *
 * Used for auto-parsing of bodies. Parsers
 * are defined on the `superagent.parse` object.
 *
 * @param {String} str
 * @return {Mixed}
 * @api private
 */

Response.prototype._parseBody = function (str) {
  var parse = request.parse[this.type];

  if (this.req._parser) {
    return this.req._parser(this, str);
  }

  if (!parse && isJSON(this.type)) {
    parse = request.parse['application/json'];
  }

  return parse && str && (str.length > 0 || str instanceof Object) ? parse(str) : null;
};
/**
 * Return an `Error` representative of this response.
 *
 * @return {Error}
 * @api public
 */


Response.prototype.toError = function () {
  var req = this.req;
  var method = req.method;
  var url = req.url;
  var msg = "cannot ".concat(method, " ").concat(url, " (").concat(this.status, ")");
  var err = new Error(msg);
  err.status = this.status;
  err.method = method;
  err.url = url;
  return err;
};
/**
 * Expose `Response`.
 */


request.Response = Response;
/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String} url
 * @api public
 */

function Request(method, url) {
  var _this = this;

  var self = this;
  this._query = this._query || [];
  this.method = method;
  this.url = url;
  this.header = {}; // preserves header name case

  this._header = {}; // coerces header names to lowercase

  this.on('end', function () {
    var err = null;
    var res = null;

    try {
      res = new Response(self);
    } catch (err_) {
      err = new Error('Parser is unable to parse the response');
      err.parse = true;
      err.original = err_; // issue #675: return the raw response if the response parsing fails

      if (self.xhr) {
        // ie9 doesn't have 'response' property
        err.rawResponse = typeof self.xhr.responseType === 'undefined' ? self.xhr.responseText : self.xhr.response; // issue #876: return the http status code if the response parsing fails

        err.status = self.xhr.status ? self.xhr.status : null;
        err.statusCode = err.status; // backwards-compat only
      } else {
        err.rawResponse = null;
        err.status = null;
      }

      return self.callback(err);
    }

    self.emit('response', res);
    var new_err;

    try {
      if (!self._isResponseOK(res)) {
        new_err = new Error(res.statusText || res.text || 'Unsuccessful HTTP response');
      }
    } catch (err_) {
      new_err = err_; // ok() callback can throw
    } // #1000 don't catch errors from the callback to avoid double calling it


    if (new_err) {
      new_err.original = err;
      new_err.response = res;
      new_err.url = _this.url;
      new_err.status = res.status;
      self.callback(new_err, res);
    } else {
      self.callback(null, res);
    }
  });
}
/**
 * Mixin `Emitter` and `RequestBase`.
 */
// eslint-disable-next-line new-cap


Emitter(Request.prototype); // eslint-disable-next-line new-cap

RequestBase(Request.prototype);
/**
 * Set Content-Type to `type`, mapping values from `request.types`.
 *
 * Examples:
 *
 *      superagent.types.xml = 'application/xml';
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.type = function (type) {
  this.set('Content-Type', request.types[type] || type);
  return this;
};
/**
 * Set Accept to `type`, mapping values from `request.types`.
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
  this.set('Accept', request.types[type] || type);
  return this;
};
/**
 * Set Authorization field value with `user` and `pass`.
 *
 * @param {String} user
 * @param {String} [pass] optional in case of using 'bearer' as type
 * @param {Object} options with 'type' property 'auto', 'basic' or 'bearer' (default 'basic')
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
      type: typeof btoa === 'function' ? 'basic' : 'auto'
    };
  }

  var encoder = function encoder(string) {
    if (typeof btoa === 'function') {
      return btoa(string);
    }

    throw new Error('Cannot use basic auth, btoa is not a function');
  };

  return this._auth(user, pass, options, encoder);
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
  if (typeof val !== 'string') val = serialize(val);
  if (val) this._query.push(val);
  return this;
};
/**
 * Queue the given `file` as an attachment to the specified `field`,
 * with optional `options` (or filename).
 *
 * ``` js
 * request.post('/upload')
 *   .attach('content', new Blob(['<a id="a"><b id="b">hey!</b></a>'], { type: "text/html"}))
 *   .end(callback);
 * ```
 *
 * @param {String} field
 * @param {Blob|File} file
 * @param {String|Object} options
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.attach = function (field, file, options) {
  if (file) {
    if (this._data) {
      throw new Error("superagent can't mix .send() and .attach()");
    }

    this._getFormData().append(field, file, options || file.name);
  }

  return this;
};

Request.prototype._getFormData = function () {
  if (!this._formData) {
    this._formData = new root.FormData();
  }

  return this._formData;
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
  }

  var fn = this._callback;
  this.clearTimeout();

  if (err) {
    if (this._maxRetries) err.retries = this._retries - 1;
    this.emit('error', err);
  }

  fn(err, res);
};
/**
 * Invoke callback with x-domain error.
 *
 * @api private
 */


Request.prototype.crossDomainError = function () {
  var err = new Error('Request has been terminated\nPossible causes: the network is offline, Origin is not allowed by Access-Control-Allow-Origin, the page is being unloaded, etc.');
  err.crossDomain = true;
  err.status = this.status;
  err.method = this.method;
  err.url = this.url;
  this.callback(err);
}; // This only warns, because the request is still likely to work


Request.prototype.agent = function () {
  console.warn('This is not supported in browser version of superagent');
  return this;
};

Request.prototype.ca = Request.prototype.agent;
Request.prototype.buffer = Request.prototype.ca; // This throws, because it can't send/receive data as expected

Request.prototype.write = function () {
  throw new Error('Streaming is not supported in browser version of superagent');
};

Request.prototype.pipe = Request.prototype.write;
/**
 * Check if `obj` is a host object,
 * we don't want to serialize these :)
 *
 * @param {Object} obj host object
 * @return {Boolean} is a host object
 * @api private
 */

Request.prototype._isHost = function (obj) {
  // Native objects stringify to [object File], [object Blob], [object FormData], etc.
  return obj && _typeof(obj) === 'object' && !Array.isArray(obj) && Object.prototype.toString.call(obj) !== '[object Object]';
};
/**
 * Initiate request, invoking callback `fn(res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.end = function (fn) {
  if (this._endCalled) {
    console.warn('Warning: .end() was called twice. This is not supported in superagent');
  }

  this._endCalled = true; // store callback

  this._callback = fn || noop; // querystring

  this._finalizeQueryString();

  this._end();
};

Request.prototype._setUploadTimeout = function () {
  var self = this; // upload timeout it's wokrs only if deadline timeout is off

  if (this._uploadTimeout && !this._uploadTimeoutTimer) {
    this._uploadTimeoutTimer = setTimeout(function () {
      self._timeoutError('Upload timeout of ', self._uploadTimeout, 'ETIMEDOUT');
    }, this._uploadTimeout);
  }
}; // eslint-disable-next-line complexity


Request.prototype._end = function () {
  if (this._aborted) return this.callback(new Error('The request has been aborted even before .end() was called'));
  var self = this;
  this.xhr = request.getXHR();
  var xhr = this.xhr;
  var data = this._formData || this._data;

  this._setTimeouts(); // state change


  xhr.onreadystatechange = function () {
    var readyState = xhr.readyState;

    if (readyState >= 2 && self._responseTimeoutTimer) {
      clearTimeout(self._responseTimeoutTimer);
    }

    if (readyState !== 4) {
      return;
    } // In IE9, reads to any property (e.g. status) off of an aborted XHR will
    // result in the error "Could not complete the operation due to error c00c023f"


    var status;

    try {
      status = xhr.status;
    } catch (_unused5) {
      status = 0;
    }

    if (!status) {
      if (self.timedout || self._aborted) return;
      return self.crossDomainError();
    }

    self.emit('end');
  }; // progress


  var handleProgress = function handleProgress(direction, e) {
    if (e.total > 0) {
      e.percent = e.loaded / e.total * 100;

      if (e.percent === 100) {
        clearTimeout(self._uploadTimeoutTimer);
      }
    }

    e.direction = direction;
    self.emit('progress', e);
  };

  if (this.hasListeners('progress')) {
    try {
      xhr.addEventListener('progress', handleProgress.bind(null, 'download'));

      if (xhr.upload) {
        xhr.upload.addEventListener('progress', handleProgress.bind(null, 'upload'));
      }
    } catch (_unused6) {// Accessing xhr.upload fails in IE from a web worker, so just pretend it doesn't exist.
      // Reported here:
      // https://connect.microsoft.com/IE/feedback/details/837245/xmlhttprequest-upload-throws-invalid-argument-when-used-from-web-worker-context
    }
  }

  if (xhr.upload) {
    this._setUploadTimeout();
  } // initiate request


  try {
    if (this.username && this.password) {
      xhr.open(this.method, this.url, true, this.username, this.password);
    } else {
      xhr.open(this.method, this.url, true);
    }
  } catch (err) {
    // see #1149
    return this.callback(err);
  } // CORS


  if (this._withCredentials) xhr.withCredentials = true; // body

  if (!this._formData && this.method !== 'GET' && this.method !== 'HEAD' && typeof data !== 'string' && !this._isHost(data)) {
    // serialize stuff
    var contentType = this._header['content-type'];

    var _serialize = this._serializer || request.serialize[contentType ? contentType.split(';')[0] : ''];

    if (!_serialize && isJSON(contentType)) {
      _serialize = request.serialize['application/json'];
    }

    if (_serialize) data = _serialize(data);
  } // set header fields


  for (var field in this.header) {
    if (this.header[field] === null) continue;
    if (Object.prototype.hasOwnProperty.call(this.header, field)) xhr.setRequestHeader(field, this.header[field]);
  }

  if (this._responseType) {
    xhr.responseType = this._responseType;
  } // send stuff


  this.emit('request', this); // IE11 xhr.send(undefined) sends 'undefined' string as POST payload (instead of nothing)
  // We need null here if data is undefined

  xhr.send(typeof data === 'undefined' ? null : data);
};

request.agent = function () {
  return new Agent();
};

['GET', 'POST', 'OPTIONS', 'PATCH', 'PUT', 'DELETE'].forEach(function (method) {
  Agent.prototype[method.toLowerCase()] = function (url, fn) {
    var req = new request.Request(method, url);

    this._setDefaults(req);

    if (fn) {
      req.end(fn);
    }

    return req;
  };
});
Agent.prototype.del = Agent.prototype.delete;
/**
 * GET `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */

request.get = function (url, data, fn) {
  var req = request('GET', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.query(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * HEAD `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.head = function (url, data, fn) {
  var req = request('HEAD', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.query(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * OPTIONS query to `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.options = function (url, data, fn) {
  var req = request('OPTIONS', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * DELETE `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} [data]
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


function del(url, data, fn) {
  var req = request('DELETE', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
}

request.del = del;
request.delete = del;
/**
 * PATCH `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} [data]
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */

request.patch = function (url, data, fn) {
  var req = request('PATCH', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * POST `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} [data]
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.post = function (url, data, fn) {
  var req = request('POST', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * PUT `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.put = function (url, data, fn) {
  var req = request('PUT', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9jbGllbnQuanMiXSwibmFtZXMiOlsicm9vdCIsIndpbmRvdyIsInNlbGYiLCJjb25zb2xlIiwid2FybiIsIkVtaXR0ZXIiLCJyZXF1aXJlIiwic2FmZVN0cmluZ2lmeSIsIlJlcXVlc3RCYXNlIiwiaXNPYmplY3QiLCJSZXNwb25zZUJhc2UiLCJBZ2VudCIsIm5vb3AiLCJtb2R1bGUiLCJleHBvcnRzIiwibWV0aG9kIiwidXJsIiwiUmVxdWVzdCIsImVuZCIsImFyZ3VtZW50cyIsImxlbmd0aCIsInJlcXVlc3QiLCJnZXRYSFIiLCJYTUxIdHRwUmVxdWVzdCIsImxvY2F0aW9uIiwicHJvdG9jb2wiLCJBY3RpdmVYT2JqZWN0IiwiRXJyb3IiLCJ0cmltIiwicyIsInJlcGxhY2UiLCJzZXJpYWxpemUiLCJvYmoiLCJwYWlycyIsImtleSIsIk9iamVjdCIsInByb3RvdHlwZSIsImhhc093blByb3BlcnR5IiwiY2FsbCIsInB1c2hFbmNvZGVkS2V5VmFsdWVQYWlyIiwiam9pbiIsInZhbCIsInVuZGVmaW5lZCIsInB1c2giLCJlbmNvZGVVUkkiLCJBcnJheSIsImlzQXJyYXkiLCJmb3JFYWNoIiwidiIsInN1YmtleSIsImVuY29kZVVSSUNvbXBvbmVudCIsInNlcmlhbGl6ZU9iamVjdCIsInBhcnNlU3RyaW5nIiwic3RyIiwic3BsaXQiLCJwYWlyIiwicG9zIiwiaSIsImxlbiIsImluZGV4T2YiLCJkZWNvZGVVUklDb21wb25lbnQiLCJzbGljZSIsInR5cGVzIiwiaHRtbCIsImpzb24iLCJ4bWwiLCJ1cmxlbmNvZGVkIiwiZm9ybSIsInBhcnNlIiwiSlNPTiIsInBhcnNlSGVhZGVyIiwibGluZXMiLCJmaWVsZHMiLCJpbmRleCIsImxpbmUiLCJmaWVsZCIsInRvTG93ZXJDYXNlIiwiaXNKU09OIiwibWltZSIsInRlc3QiLCJSZXNwb25zZSIsInJlcSIsInhociIsInRleHQiLCJyZXNwb25zZVR5cGUiLCJyZXNwb25zZVRleHQiLCJzdGF0dXNUZXh0Iiwic3RhdHVzIiwiX3NldFN0YXR1c1Byb3BlcnRpZXMiLCJoZWFkZXJzIiwiZ2V0QWxsUmVzcG9uc2VIZWFkZXJzIiwiaGVhZGVyIiwiZ2V0UmVzcG9uc2VIZWFkZXIiLCJfc2V0SGVhZGVyUHJvcGVydGllcyIsIl9yZXNwb25zZVR5cGUiLCJib2R5IiwicmVzcG9uc2UiLCJfcGFyc2VCb2R5IiwidHlwZSIsIl9wYXJzZXIiLCJ0b0Vycm9yIiwibXNnIiwiZXJyIiwiX3F1ZXJ5IiwiX2hlYWRlciIsIm9uIiwicmVzIiwiZXJyXyIsIm9yaWdpbmFsIiwicmF3UmVzcG9uc2UiLCJzdGF0dXNDb2RlIiwiY2FsbGJhY2siLCJlbWl0IiwibmV3X2VyciIsIl9pc1Jlc3BvbnNlT0siLCJzZXQiLCJhY2NlcHQiLCJhdXRoIiwidXNlciIsInBhc3MiLCJvcHRpb25zIiwiYnRvYSIsImVuY29kZXIiLCJzdHJpbmciLCJfYXV0aCIsInF1ZXJ5IiwiYXR0YWNoIiwiZmlsZSIsIl9kYXRhIiwiX2dldEZvcm1EYXRhIiwiYXBwZW5kIiwibmFtZSIsIl9mb3JtRGF0YSIsIkZvcm1EYXRhIiwiX3Nob3VsZFJldHJ5IiwiX3JldHJ5IiwiZm4iLCJfY2FsbGJhY2siLCJjbGVhclRpbWVvdXQiLCJfbWF4UmV0cmllcyIsInJldHJpZXMiLCJfcmV0cmllcyIsImNyb3NzRG9tYWluRXJyb3IiLCJjcm9zc0RvbWFpbiIsImFnZW50IiwiY2EiLCJidWZmZXIiLCJ3cml0ZSIsInBpcGUiLCJfaXNIb3N0IiwidG9TdHJpbmciLCJfZW5kQ2FsbGVkIiwiX2ZpbmFsaXplUXVlcnlTdHJpbmciLCJfZW5kIiwiX3NldFVwbG9hZFRpbWVvdXQiLCJfdXBsb2FkVGltZW91dCIsIl91cGxvYWRUaW1lb3V0VGltZXIiLCJzZXRUaW1lb3V0IiwiX3RpbWVvdXRFcnJvciIsIl9hYm9ydGVkIiwiZGF0YSIsIl9zZXRUaW1lb3V0cyIsIm9ucmVhZHlzdGF0ZWNoYW5nZSIsInJlYWR5U3RhdGUiLCJfcmVzcG9uc2VUaW1lb3V0VGltZXIiLCJ0aW1lZG91dCIsImhhbmRsZVByb2dyZXNzIiwiZGlyZWN0aW9uIiwiZSIsInRvdGFsIiwicGVyY2VudCIsImxvYWRlZCIsImhhc0xpc3RlbmVycyIsImFkZEV2ZW50TGlzdGVuZXIiLCJiaW5kIiwidXBsb2FkIiwidXNlcm5hbWUiLCJwYXNzd29yZCIsIm9wZW4iLCJfd2l0aENyZWRlbnRpYWxzIiwid2l0aENyZWRlbnRpYWxzIiwiY29udGVudFR5cGUiLCJfc2VyaWFsaXplciIsInNldFJlcXVlc3RIZWFkZXIiLCJzZW5kIiwiX3NldERlZmF1bHRzIiwiZGVsIiwiZGVsZXRlIiwiZ2V0IiwiaGVhZCIsInBhdGNoIiwicG9zdCIsInB1dCJdLCJtYXBwaW5ncyI6Ijs7OztBQUFBOzs7QUFJQSxJQUFJQSxJQUFKOztBQUNBLElBQUksT0FBT0MsTUFBUCxLQUFrQixXQUF0QixFQUFtQztBQUNqQztBQUNBRCxFQUFBQSxJQUFJLEdBQUdDLE1BQVA7QUFDRCxDQUhELE1BR08sSUFBSSxPQUFPQyxJQUFQLEtBQWdCLFdBQXBCLEVBQWlDO0FBQ3RDO0FBQ0FDLEVBQUFBLE9BQU8sQ0FBQ0MsSUFBUixDQUNFLHFFQURGO0FBR0FKLEVBQUFBLElBQUksU0FBSjtBQUNELENBTk0sTUFNQTtBQUNMO0FBQ0FBLEVBQUFBLElBQUksR0FBR0UsSUFBUDtBQUNEOztBQUVELElBQU1HLE9BQU8sR0FBR0MsT0FBTyxDQUFDLG1CQUFELENBQXZCOztBQUNBLElBQU1DLGFBQWEsR0FBR0QsT0FBTyxDQUFDLHFCQUFELENBQTdCOztBQUNBLElBQU1FLFdBQVcsR0FBR0YsT0FBTyxDQUFDLGdCQUFELENBQTNCOztBQUNBLElBQU1HLFFBQVEsR0FBR0gsT0FBTyxDQUFDLGFBQUQsQ0FBeEI7O0FBQ0EsSUFBTUksWUFBWSxHQUFHSixPQUFPLENBQUMsaUJBQUQsQ0FBNUI7O0FBQ0EsSUFBTUssS0FBSyxHQUFHTCxPQUFPLENBQUMsY0FBRCxDQUFyQjtBQUVBOzs7OztBQUlBLFNBQVNNLElBQVQsR0FBZ0IsQ0FBRTtBQUVsQjs7Ozs7QUFJ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QUFPdkQsR0FBUDtBQUNELENBVkQiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFJvb3QgcmVmZXJlbmNlIGZvciBpZnJhbWVzLlxuICovXG5cbmxldCByb290O1xuaWYgKHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnKSB7XG4gIC8vIEJyb3dzZXIgd2luZG93XG4gIHJvb3QgPSB3aW5kb3c7XG59IGVsc2UgaWYgKHR5cGVvZiBzZWxmID09PSAndW5kZWZpbmVkJykge1xuICAvLyBPdGhlciBlbnZpcm9ubWVudHNcbiAgY29uc29sZS53YXJuKFxuICAgICdVc2luZyBicm93c2VyLW9ubHkgdmVyc2lvbiBvZiBzdXBlcmFnZW50IGluIG5vbi1icm93c2VyIGVudmlyb25tZW50J1xuICApO1xuICByb290ID0gdGhpcztcbn0gZWxzZSB7XG4gIC8vIFdlYiBXb3JrZXJcbiAgcm9vdCA9IHNlbGY7XG59XG5cbmNvbnN0IEVtaXR0ZXIgPSByZXF1aXJlKCdjb21wb25lbnQtZW1pdHRlcicpO1xuY29uc3Qgc2FmZVN0cmluZ2lmeSA9IHJlcXVpcmUoJ2Zhc3Qtc2FmZS1zdHJpbmdpZnknKTtcbmNvbnN0IFJlcXVlc3RCYXNlID0gcmVxdWlyZSgnLi9yZXF1ZXN0LWJhc2UnKTtcbmNvbnN0IGlzT2JqZWN0ID0gcmVxdWlyZSgnLi9pcy1vYmplY3QnKTtcbmNvbnN0IFJlc3BvbnNlQmFzZSA9IHJlcXVpcmUoJy4vcmVzcG9uc2UtYmFzZScpO1xuY29uc3QgQWdlbnQgPSByZXF1aXJlKCcuL2FnZW50LWJhc2UnKTtcblxuLyoqXG4gKiBOb29wLlxuICovXG5cbmZ1bmN0aW9uIG5vb3AoKSB7fVxuXG4vKipcbiAqIEV4cG9zZSBgcmVxdWVzdGAuXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihtZXRob2QsIHVybCkge1xuICAvLyBjYWxsYmFja1xuICBpZiAodHlwZW9mIHVybCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KCdHRVQnLCBtZXRob2QpLmVuZCh1cmwpO1xuICB9XG5cbiAgLy8gdXJsIGZpcnN0XG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QoJ0dFVCcsIG1ldGhvZCk7XG4gIH1cblxuICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdChtZXRob2QsIHVybCk7XG59O1xuXG5leHBvcnRzID0gbW9kdWxlLmV4cG9ydHM7XG5cbmNvbnN0IHJlcXVlc3QgPSBleHBvcnRzO1xuXG5leHBvcnRzLlJlcXVlc3QgPSBSZXF1ZXN0O1xuXG4vKipcbiAqIERldGVybWluZSBYSFIuXG4gKi9cblxucmVxdWVzdC5nZXRYSFIgPSAoKSA9PiB7XG4gIGlmIChcbiAgICByb290LlhNTEh0dHBSZXF1ZXN0ICYmXG4gICAgKCFyb290LmxvY2F0aW9uIHx8XG4gICAgICByb290LmxvY2F0aW9uLnByb3RvY29sICE9PSAnZmlsZTonIHx8XG4gICAgICAhcm9vdC5BY3RpdmVYT2JqZWN0KVxuICApIHtcbiAgICByZXR1cm4gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XG4gIH1cblxuICB0cnkge1xuICAgIHJldHVybiBuZXcgQWN0aXZlWE9iamVjdCgnTWljcm9zb2Z0LlhNTEhUVFAnKTtcbiAgfSBjYXRjaCB7fVxuXG4gIHRyeSB7XG4gICAgcmV0dXJuIG5ldyBBY3RpdmVYT2JqZWN0KCdNc3htbDIuWE1MSFRUUC42LjAnKTtcbiAgfSBjYXRjaCB7fVxuXG4gIHRyeSB7XG4gICAgcmV0dXJuIG5ldyBBY3RpdmVYT2JqZWN0KCdNc3htbDIuWE1MSFRUUC4zLjAnKTtcbiAgfSBjYXRjaCB7fVxuXG4gIHRyeSB7XG4gICAgcmV0dXJuIG5ldyBBY3RpdmVYT2JqZWN0KCdNc3htbDIuWE1MSFRUUCcpO1xuICB9IGNhdGNoIHt9XG5cbiAgdGhyb3cgbmV3IEVycm9yKCdCcm93c2VyLW9ubHkgdmVyc2lvbiBvZiBzdXBlcmFnZW50IGNvdWxkIG5vdCBmaW5kIFhIUicpO1xufTtcblxuLyoqXG4gKiBSZW1vdmVzIGxlYWRpbmcgYW5kIHRyYWlsaW5nIHdoaXRlc3BhY2UsIGFkZGVkIHRvIHN1cHBvcnQgSUUuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHNcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmNvbnN0IHRyaW0gPSAnJy50cmltID8gcyA9PiBzLnRyaW0oKSA6IHMgPT4gcy5yZXBsYWNlKC8oXlxccyp8XFxzKiQpL2csICcnKTtcblxuLyoqXG4gKiBTZXJpYWxpemUgdGhlIGdpdmVuIGBvYmpgLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHNlcmlhbGl6ZShvYmopIHtcbiAgaWYgKCFpc09iamVjdChvYmopKSByZXR1cm4gb2JqO1xuICBjb25zdCBwYWlycyA9IFtdO1xuICBmb3IgKGNvbnN0IGtleSBpbiBvYmopIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KSlcbiAgICAgIHB1c2hFbmNvZGVkS2V5VmFsdWVQYWlyKHBhaXJzLCBrZXksIG9ialtrZXldKTtcbiAgfVxuXG4gIHJldHVybiBwYWlycy5qb2luKCcmJyk7XG59XG5cbi8qKlxuICogSGVscHMgJ3NlcmlhbGl6ZScgd2l0aCBzZXJpYWxpemluZyBhcnJheXMuXG4gKiBNdXRhdGVzIHRoZSBwYWlycyBhcnJheS5cbiAqXG4gKiBAcGFyYW0ge0FycmF5fSBwYWlyc1xuICogQHBhcmFtIHtTdHJpbmd9IGtleVxuICogQHBhcmFtIHtNaXhlZH0gdmFsXG4gKi9cblxuZnVuY3Rpb24gcHVzaEVuY29kZWRLZXlWYWx1ZVBhaXIocGFpcnMsIGtleSwgdmFsKSB7XG4gIGlmICh2YWwgPT09IHVuZGVmaW5lZCkgcmV0dXJuO1xuICBpZiAodmFsID09PSBudWxsKSB7XG4gICAgcGFpcnMucHVzaChlbmNvZGVVUkkoa2V5KSk7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkodmFsKSkge1xuICAgIHZhbC5mb3JFYWNoKHYgPT4ge1xuICAgICAgcHVzaEVuY29kZWRLZXlWYWx1ZVBhaXIocGFpcnMsIGtleSwgdik7XG4gICAgfSk7XG4gIH0gZWxzZSBpZiAoaXNPYmplY3QodmFsKSkge1xuICAgIGZvciAoY29uc3Qgc3Via2V5IGluIHZhbCkge1xuICAgICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbCh2YWwsIHN1YmtleSkpXG4gICAgICAgIHB1c2hFbmNvZGVkS2V5VmFsdWVQYWlyKHBhaXJzLCBgJHtrZXl9WyR7c3Via2V5fV1gLCB2YWxbc3Via2V5XSk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIHBhaXJzLnB1c2goZW5jb2RlVVJJKGtleSkgKyAnPScgKyBlbmNvZGVVUklDb21wb25lbnQodmFsKSk7XG4gIH1cbn1cblxuLyoqXG4gKiBFeHBvc2Ugc2VyaWFsaXphdGlvbiBtZXRob2QuXG4gKi9cblxucmVxdWVzdC5zZXJpYWxpemVPYmplY3QgPSBzZXJpYWxpemU7XG5cbi8qKlxuICogUGFyc2UgdGhlIGdpdmVuIHgtd3d3LWZvcm0tdXJsZW5jb2RlZCBgc3RyYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gc3RyXG4gKiBAcmV0dXJuIHtPYmplY3R9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBwYXJzZVN0cmluZyhzdHIpIHtcbiAgY29uc3Qgb2JqID0ge307XG4gIGNvbnN0IHBhaXJzID0gc3RyLnNwbGl0KCcmJyk7XG4gIGxldCBwYWlyO1xuICBsZXQgcG9zO1xuXG4gIGZvciAobGV0IGkgPSAwLCBsZW4gPSBwYWlycy5sZW5ndGg7IGkgPCBsZW47ICsraSkge1xuICAgIHBhaXIgPSBwYWlyc1tpXTtcbiAgICBwb3MgPSBwYWlyLmluZGV4T2YoJz0nKTtcbiAgICBpZiAocG9zID09PSAtMSkge1xuICAgICAgb2JqW2RlY29kZVVSSUNvbXBvbmVudChwYWlyKV0gPSAnJztcbiAgICB9IGVsc2Uge1xuICAgICAgb2JqW2RlY29kZVVSSUNvbXBvbmVudChwYWlyLnNsaWNlKDAsIHBvcykpXSA9IGRlY29kZVVSSUNvbXBvbmVudChcbiAgICAgICAgcGFpci5zbGljZShwb3MgKyAxKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gb2JqO1xufVxuXG4vKipcbiAqIEV4cG9zZSBwYXJzZXIuXG4gKi9cblxucmVxdWVzdC5wYXJzZVN0cmluZyA9IHBhcnNlU3RyaW5nO1xuXG4vKipcbiAqIERlZmF1bHQgTUlNRSB0eXBlIG1hcC5cbiAqXG4gKiAgICAgc3VwZXJhZ2VudC50eXBlcy54bWwgPSAnYXBwbGljYXRpb24veG1sJztcbiAqXG4gKi9cblxucmVxdWVzdC50eXBlcyA9IHtcbiAgaHRtbDogJ3RleHQvaHRtbCcsXG4gIGpzb246ICdhcHBsaWNhdGlvbi9qc29uJyxcbiAgeG1sOiAndGV4dC94bWwnLFxuICB1cmxlbmNvZGVkOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxcbiAgZm9ybTogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCcsXG4gICdmb3JtLWRhdGEnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xufTtcblxuLyoqXG4gKiBEZWZhdWx0IHNlcmlhbGl6YXRpb24gbWFwLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnNlcmlhbGl6ZVsnYXBwbGljYXRpb24veG1sJ10gPSBmdW5jdGlvbihvYmope1xuICogICAgICAgcmV0dXJuICdnZW5lcmF0ZWQgeG1sIGhlcmUnO1xuICogICAgIH07XG4gKlxuICovXG5cbnJlcXVlc3Quc2VyaWFsaXplID0ge1xuICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJzogc2VyaWFsaXplLFxuICAnYXBwbGljYXRpb24vanNvbic6IHNhZmVTdHJpbmdpZnlcbn07XG5cbi8qKlxuICogRGVmYXVsdCBwYXJzZXJzLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnBhcnNlWydhcHBsaWNhdGlvbi94bWwnXSA9IGZ1bmN0aW9uKHN0cil7XG4gKiAgICAgICByZXR1cm4geyBvYmplY3QgcGFyc2VkIGZyb20gc3RyIH07XG4gKiAgICAgfTtcbiAqXG4gKi9cblxucmVxdWVzdC5wYXJzZSA9IHtcbiAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc6IHBhcnNlU3RyaW5nLFxuICAnYXBwbGljYXRpb24vanNvbic6IEpTT04ucGFyc2Vcbn07XG5cbi8qKlxuICogUGFyc2UgdGhlIGdpdmVuIGhlYWRlciBgc3RyYCBpbnRvXG4gKiBhbiBvYmplY3QgY29udGFpbmluZyB0aGUgbWFwcGVkIGZpZWxkcy5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gc3RyXG4gKiBAcmV0dXJuIHtPYmplY3R9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBwYXJzZUhlYWRlcihzdHIpIHtcbiAgY29uc3QgbGluZXMgPSBzdHIuc3BsaXQoL1xccj9cXG4vKTtcbiAgY29uc3QgZmllbGRzID0ge307XG4gIGxldCBpbmRleDtcbiAgbGV0IGxpbmU7XG4gIGxldCBmaWVsZDtcbiAgbGV0IHZhbDtcblxuICBmb3IgKGxldCBpID0gMCwgbGVuID0gbGluZXMubGVuZ3RoOyBpIDwgbGVuOyArK2kpIHtcbiAgICBsaW5lID0gbGluZXNbaV07XG4gICAgaW5kZXggPSBsaW5lLmluZGV4T2YoJzonKTtcbiAgICBpZiAoaW5kZXggPT09IC0xKSB7XG4gICAgICAvLyBjb3VsZCBiZSBlbXB0eSBsaW5lLCBqdXN0IHNraXAgaXRcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cblxuICAgIGZpZWxkID0gbGluZS5zbGljZSgwLCBpbmRleCkudG9Mb3dlckNhc2UoKTtcbiAgICB2YWwgPSB0cmltKGxpbmUuc2xpY2UoaW5kZXggKyAxKSk7XG4gICAgZmllbGRzW2ZpZWxkXSA9IHZhbDtcbiAgfVxuXG4gIHJldHVybiBmaWVsZHM7XG59XG5cbi8qKlxuICogQ2hlY2sgaWYgYG1pbWVgIGlzIGpzb24gb3IgaGFzICtqc29uIHN0cnVjdHVyZWQgc3ludGF4IHN1ZmZpeC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gbWltZVxuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIGlzSlNPTihtaW1lKSB7XG4gIC8vIHNob3VsZCBtYXRjaCAvanNvbiBvciAranNvblxuICAvLyBidXQgbm90IC9qc29uLXNlcVxuICByZXR1cm4gL1svK11qc29uKCR8W14tXFx3XSkvLnRlc3QobWltZSk7XG59XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBhIG5ldyBgUmVzcG9uc2VgIHdpdGggdGhlIGdpdmVuIGB4aHJgLlxuICpcbiAqICAtIHNldCBmbGFncyAoLm9rLCAuZXJyb3IsIGV0YylcbiAqICAtIHBhcnNlIGhlYWRlclxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICBBbGlhc2luZyBgc3VwZXJhZ2VudGAgYXMgYHJlcXVlc3RgIGlzIG5pY2U6XG4gKlxuICogICAgICByZXF1ZXN0ID0gc3VwZXJhZ2VudDtcbiAqXG4gKiAgV2UgY2FuIHVzZSB0aGUgcHJvbWlzZS1saWtlIEFQSSwgb3IgcGFzcyBjYWxsYmFja3M6XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnLycpLmVuZChmdW5jdGlvbihyZXMpe30pO1xuICogICAgICByZXF1ZXN0LmdldCgnLycsIGZ1bmN0aW9uKHJlcyl7fSk7XG4gKlxuICogIFNlbmRpbmcgZGF0YSBjYW4gYmUgY2hhaW5lZDpcbiAqXG4gKiAgICAgIHJlcXVlc3RcbiAqICAgICAgICAucG9zdCgnL3VzZXInKVxuICogICAgICAgIC5zZW5kKHsgbmFtZTogJ3RqJyB9KVxuICogICAgICAgIC5lbmQoZnVuY3Rpb24ocmVzKXt9KTtcbiAqXG4gKiAgT3IgcGFzc2VkIHRvIGAuc2VuZCgpYDpcbiAqXG4gKiAgICAgIHJlcXVlc3RcbiAqICAgICAgICAucG9zdCgnL3VzZXInKVxuICogICAgICAgIC5zZW5kKHsgbmFtZTogJ3RqJyB9LCBmdW5jdGlvbihyZXMpe30pO1xuICpcbiAqICBPciBwYXNzZWQgdG8gYC5wb3N0KClgOlxuICpcbiAqICAgICAgcmVxdWVzdFxuICogICAgICAgIC5wb3N0KCcvdXNlcicsIHsgbmFtZTogJ3RqJyB9KVxuICogICAgICAgIC5lbmQoZnVuY3Rpb24ocmVzKXt9KTtcbiAqXG4gKiBPciBmdXJ0aGVyIHJlZHVjZWQgdG8gYSBzaW5nbGUgY2FsbCBmb3Igc2ltcGxlIGNhc2VzOlxuICpcbiAqICAgICAgcmVxdWVzdFxuICogICAgICAgIC5wb3N0KCcvdXNlcicsIHsgbmFtZTogJ3RqJyB9LCBmdW5jdGlvbihyZXMpe30pO1xuICpcbiAqIEBwYXJhbSB7WE1MSFRUUFJlcXVlc3R9IHhoclxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIFJlc3BvbnNlKHJlcSkge1xuICB0aGlzLnJlcSA9IHJlcTtcbiAgdGhpcy54aHIgPSB0aGlzLnJlcS54aHI7XG4gIC8vIHJlc3BvbnNlVGV4dCBpcyBhY2Nlc3NpYmxlIG9ubHkgaWYgcmVzcG9uc2VUeXBlIGlzICcnIG9yICd0ZXh0JyBhbmQgb24gb2xkZXIgYnJvd3NlcnNcbiAgdGhpcy50ZXh0ID1cbiAgICAodGhpcy5yZXEubWV0aG9kICE9PSAnSEVBRCcgJiZcbiAgICAgICh0aGlzLnhoci5yZXNwb25zZVR5cGUgPT09ICcnIHx8IHRoaXMueGhyLnJlc3BvbnNlVHlwZSA9PT0gJ3RleHQnKSkgfHxcbiAgICB0eXBlb2YgdGhpcy54aHIucmVzcG9uc2VUeXBlID09PSAndW5kZWZpbmVkJ1xuICAgICAgPyB0aGlzLnhoci5yZXNwb25zZVRleHRcbiAgICAgIDogbnVsbDtcbiAgdGhpcy5zdGF0dXNUZXh0ID0gdGhpcy5yZXEueGhyLnN0YXR1c1RleHQ7XG4gIGxldCB7IHN0YXR1cyB9ID0gdGhpcy54aHI7XG4gIC8vIGhhbmRsZSBJRTkgYnVnOiBodHRwOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzEwMDQ2OTcyL21zaWUtcmV0dXJucy1zdGF0dXMtY29kZS1vZi0xMjIzLWZvci1hamF4LXJlcXVlc3RcbiAgaWYgKHN0YXR1cyA9PT0gMTIyMykge1xuICAgIHN0YXR1cyA9IDIwNDtcbiAgfVxuXG4gIHRoaXMuX3NldFN0YXR1c1Byb3BlcnRpZXMoc3RhdHVzKTtcbiAgdGhpcy5oZWFkZXJzID0gcGFyc2VIZWFkZXIodGhpcy54aHIuZ2V0QWxsUmVzcG9uc2VIZWFkZXJzKCkpO1xuICB0aGlzLmhlYWRlciA9IHRoaXMuaGVhZGVycztcbiAgLy8gZ2V0QWxsUmVzcG9uc2VIZWFkZXJzIHNvbWV0aW1lcyBmYWxzZWx5IHJldHVybnMgXCJcIiBmb3IgQ09SUyByZXF1ZXN0cywgYnV0XG4gIC8vIGdldFJlc3BvbnNlSGVhZGVyIHN0aWxsIHdvcmtzLiBzbyB3ZSBnZXQgY29udGVudC10eXBlIGV2ZW4gaWYgZ2V0dGluZ1xuICAvLyBvdGhlciBoZWFkZXJzIGZhaWxzLlxuICB0aGlzLmhlYWRlclsnY29udGVudC10eXBlJ10gPSB0aGlzLnhoci5nZXRSZXNwb25zZUhlYWRlcignY29udGVudC10eXBlJyk7XG4gIHRoaXMuX3NldEhlYWRlclByb3BlcnRpZXModGhpcy5oZWFkZXIpO1xuXG4gIGlmICh0aGlzLnRleHQgPT09IG51bGwgJiYgcmVxLl9yZXNwb25zZVR5cGUpIHtcbiAgICB0aGlzLmJvZHkgPSB0aGlzLnhoci5yZXNwb25zZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLmJvZHkgPVxuICAgICAgdGhpcy5yZXEubWV0aG9kID09PSAnSEVBRCdcbiAgICAgICAgPyBudWxsXG4gICAgICAgIDogdGhpcy5fcGFyc2VCb2R5KHRoaXMudGV4dCA/IHRoaXMudGV4dCA6IHRoaXMueGhyLnJlc3BvbnNlKTtcbiAgfVxufVxuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbmV3LWNhcFxuUmVzcG9uc2VCYXNlKFJlc3BvbnNlLnByb3RvdHlwZSk7XG5cbi8qKlxuICogUGFyc2UgdGhlIGdpdmVuIGJvZHkgYHN0cmAuXG4gKlxuICogVXNlZCBmb3IgYXV0by1wYXJzaW5nIG9mIGJvZGllcy4gUGFyc2Vyc1xuICogYXJlIGRlZmluZWQgb24gdGhlIGBzdXBlcmFnZW50LnBhcnNlYCBvYmplY3QuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHN0clxuICogQHJldHVybiB7TWl4ZWR9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXNwb25zZS5wcm90b3R5cGUuX3BhcnNlQm9keSA9IGZ1bmN0aW9uKHN0cikge1xuICBsZXQgcGFyc2UgPSByZXF1ZXN0LnBhcnNlW3RoaXMudHlwZV07XG4gIGlmICh0aGlzLnJlcS5fcGFyc2VyKSB7XG4gICAgcmV0dXJuIHRoaXMucmVxLl9wYXJzZXIodGhpcywgc3RyKTtcbiAgfVxuXG4gIGlmICghcGFyc2UgJiYgaXNKU09OKHRoaXMudHlwZSkpIHtcbiAgICBwYXJzZSA9IHJlcXVlc3QucGFyc2VbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgfVxuXG4gIHJldHVybiBwYXJzZSAmJiBzdHIgJiYgKHN0ci5sZW5ndGggPiAwIHx8IHN0ciBpbnN0YW5jZW9mIE9iamVjdClcbiAgICA/IHBhcnNlKHN0cilcbiAgICA6IG51bGw7XG59O1xuXG4vKipcbiAqIFJldHVybiBhbiBgRXJyb3JgIHJlcHJlc2VudGF0aXZlIG9mIHRoaXMgcmVzcG9uc2UuXG4gKlxuICogQHJldHVybiB7RXJyb3J9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlc3BvbnNlLnByb3RvdHlwZS50b0Vycm9yID0gZnVuY3Rpb24oKSB7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuICBjb25zdCB7IG1ldGhvZCB9ID0gcmVxO1xuICBjb25zdCB7IHVybCB9ID0gcmVxO1xuXG4gIGNvbnN0IG1zZyA9IGBjYW5ub3QgJHttZXRob2R9ICR7dXJsfSAoJHt0aGlzLnN0YXR1c30pYDtcbiAgY29uc3QgZXJyID0gbmV3IEVycm9yKG1zZyk7XG4gIGVyci5zdGF0dXMgPSB0aGlzLnN0YXR1cztcbiAgZXJyLm1ldGhvZCA9IG1ldGhvZDtcbiAgZXJyLnVybCA9IHVybDtcblxuICByZXR1cm4gZXJyO1xufTtcblxuLyoqXG4gKiBFeHBvc2UgYFJlc3BvbnNlYC5cbiAqL1xuXG5yZXF1ZXN0LlJlc3BvbnNlID0gUmVzcG9uc2U7XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBhIG5ldyBgUmVxdWVzdGAgd2l0aCB0aGUgZ2l2ZW4gYG1ldGhvZGAgYW5kIGB1cmxgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtZXRob2RcbiAqIEBwYXJhbSB7U3RyaW5nfSB1cmxcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gUmVxdWVzdChtZXRob2QsIHVybCkge1xuICBjb25zdCBzZWxmID0gdGhpcztcbiAgdGhpcy5fcXVlcnkgPSB0aGlzLl9xdWVyeSB8fCBbXTtcbiAgdGhpcy5tZXRob2QgPSBtZXRob2Q7XG4gIHRoaXMudXJsID0gdXJsO1xuICB0aGlzLmhlYWRlciA9IHt9OyAvLyBwcmVzZXJ2ZXMgaGVhZGVyIG5hbWUgY2FzZVxuICB0aGlzLl9oZWFkZXIgPSB7fTsgLy8gY29lcmNlcyBoZWFkZXIgbmFtZXMgdG8gbG93ZXJjYXNlXG4gIHRoaXMub24oJ2VuZCcsICgpID0+IHtcbiAgICBsZXQgZXJyID0gbnVsbDtcbiAgICBsZXQgcmVzID0gbnVsbDtcblxuICAgIHRyeSB7XG4gICAgICByZXMgPSBuZXcgUmVzcG9uc2Uoc2VsZik7XG4gICAgfSBjYXRjaCAoZXJyXykge1xuICAgICAgZXJyID0gbmV3IEVycm9yKCdQYXJzZXIgaXMgdW5hYmxlIHRvIHBhcnNlIHRoZSByZXNwb25zZScpO1xuICAgICAgZXJyLnBhcnNlID0gdHJ1ZTtcbiAgICAgIGVyci5vcmlnaW5hbCA9IGVycl87XG4gICAgICAvLyBpc3N1ZSAjNjc1OiByZXR1cm4gdGhlIHJhdyByZXNwb25zZSBpZiB0aGUgcmVzcG9uc2UgcGFyc2luZyBmYWlsc1xuICAgICAgaWYgKHNlbGYueGhyKSB7XG4gICAgICAgIC8vIGllOSBkb2Vzbid0IGhhdmUgJ3Jlc3BvbnNlJyBwcm9wZXJ0eVxuICAgICAgICBlcnIucmF3UmVzcG9uc2UgPVxuICAgICAgICAgIHR5cGVvZiBzZWxmLnhoci5yZXNwb25zZVR5cGUgPT09ICd1bmRlZmluZWQnXG4gICAgICAgICAgICA/IHNlbGYueGhyLnJlc3BvbnNlVGV4dFxuICAgICAgICAgICAgOiBzZWxmLnhoci5yZXNwb25zZTtcbiAgICAgICAgLy8gaXNzdWUgIzg3NjogcmV0dXJuIHRoZSBodHRwIHN0YXR1cyBjb2RlIGlmIHRoZSByZXNwb25zZSBwYXJzaW5nIGZhaWxzXG4gICAgICAgIGVyci5zdGF0dXMgPSBzZWxmLnhoci5zdGF0dXMgPyBzZWxmLnhoci5zdGF0dXMgOiBudWxsO1xuICAgICAgICBlcnIuc3RhdHVzQ29kZSA9IGVyci5zdGF0dXM7IC8vIGJhY2t3YXJkcy1jb21wYXQgb25seVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZXJyLnJhd1Jlc3BvbnNlID0gbnVsbDtcbiAgICAgICAgZXJyLnN0YXR1cyA9IG51bGw7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBzZWxmLmNhbGxiYWNrKGVycik7XG4gICAgfVxuXG4gICAgc2VsZi5lbWl0KCdyZXNwb25zZScsIHJlcyk7XG5cbiAgICBsZXQgbmV3X2VycjtcbiAgICB0cnkge1xuICAgICAgaWYgKCFzZWxmLl9pc1Jlc3BvbnNlT0socmVzKSkge1xuICAgICAgICBuZXdfZXJyID0gbmV3IEVycm9yKFxuICAgICAgICAgIHJlcy5zdGF0dXNUZXh0IHx8IHJlcy50ZXh0IHx8ICdVbnN1Y2Nlc3NmdWwgSFRUUCByZXNwb25zZSdcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJfKSB7XG4gICAgICBuZXdfZXJyID0gZXJyXzsgLy8gb2soKSBjYWxsYmFjayBjYW4gdGhyb3dcbiAgICB9XG5cbiAgICAvLyAjMTAwMCBkb24ndCBjYXRjaCBlcnJvcnMgZnJvbSB0aGUgY2FsbGJhY2sgdG8gYXZvaWQgZG91YmxlIGNhbGxpbmcgaXRcbiAgICBpZiAobmV3X2Vycikge1xuICAgICAgbmV3X2Vyci5vcmlnaW5hbCA9IGVycjtcbiAgICAgIG5ld19lcnIucmVzcG9uc2UgPSByZXM7XG4gICAgICBuZXdfZXJyLnVybCA9IHRoaXMudXJsO1xuICAgICAgbmV3X2Vyci5zdGF0dXMgPSByZXMuc3RhdHVzO1xuICAgICAgc2VsZi5jYWxsYmFjayhuZXdfZXJyLCByZXMpO1xuICAgIH0gZWxzZSB7XG4gICAgICBzZWxmLmNhbGxiYWNrKG51bGwsIHJlcyk7XG4gICAgfVxuICB9KTtcbn1cblxuLyoqXG4gKiBNaXhpbiBgRW1pdHRlcmAgYW5kIGBSZXF1ZXN0QmFzZWAuXG4gKi9cblxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5ldy1jYXBcbkVtaXR0ZXIoUmVxdWVzdC5wcm90b3R5cGUpO1xuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5ldy1jYXBcblJlcXVlc3RCYXNlKFJlcXVlc3QucHJvdG90eXBlKTtcblxuLyoqXG4gKiBTZXQgQ29udGVudC1UeXBlIHRvIGB0eXBlYCwgbWFwcGluZyB2YWx1ZXMgZnJvbSBgcmVxdWVzdC50eXBlc2AuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAgICBzdXBlcmFnZW50LnR5cGVzLnhtbCA9ICdhcHBsaWNhdGlvbi94bWwnO1xuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgneG1sJylcbiAqICAgICAgICAuc2VuZCh4bWxzdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogICAgICByZXF1ZXN0LnBvc3QoJy8nKVxuICogICAgICAgIC50eXBlKCdhcHBsaWNhdGlvbi94bWwnKVxuICogICAgICAgIC5zZW5kKHhtbHN0cmluZylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdHlwZVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnR5cGUgPSBmdW5jdGlvbih0eXBlKSB7XG4gIHRoaXMuc2V0KCdDb250ZW50LVR5cGUnLCByZXF1ZXN0LnR5cGVzW3R5cGVdIHx8IHR5cGUpO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IEFjY2VwdCB0byBgdHlwZWAsIG1hcHBpbmcgdmFsdWVzIGZyb20gYHJlcXVlc3QudHlwZXNgLlxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICAgICAgc3VwZXJhZ2VudC50eXBlcy5qc29uID0gJ2FwcGxpY2F0aW9uL2pzb24nO1xuICpcbiAqICAgICAgcmVxdWVzdC5nZXQoJy9hZ2VudCcpXG4gKiAgICAgICAgLmFjY2VwdCgnanNvbicpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnL2FnZW50JylcbiAqICAgICAgICAuYWNjZXB0KCdhcHBsaWNhdGlvbi9qc29uJylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gYWNjZXB0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYWNjZXB0ID0gZnVuY3Rpb24odHlwZSkge1xuICB0aGlzLnNldCgnQWNjZXB0JywgcmVxdWVzdC50eXBlc1t0eXBlXSB8fCB0eXBlKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBBdXRob3JpemF0aW9uIGZpZWxkIHZhbHVlIHdpdGggYHVzZXJgIGFuZCBgcGFzc2AuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVzZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSBbcGFzc10gb3B0aW9uYWwgaW4gY2FzZSBvZiB1c2luZyAnYmVhcmVyJyBhcyB0eXBlXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9ucyB3aXRoICd0eXBlJyBwcm9wZXJ0eSAnYXV0bycsICdiYXNpYycgb3IgJ2JlYXJlcicgKGRlZmF1bHQgJ2Jhc2ljJylcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdXRoID0gZnVuY3Rpb24odXNlciwgcGFzcywgb3B0aW9ucykge1xuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMSkgcGFzcyA9ICcnO1xuICBpZiAodHlwZW9mIHBhc3MgPT09ICdvYmplY3QnICYmIHBhc3MgIT09IG51bGwpIHtcbiAgICAvLyBwYXNzIGlzIG9wdGlvbmFsIGFuZCBjYW4gYmUgcmVwbGFjZWQgd2l0aCBvcHRpb25zXG4gICAgb3B0aW9ucyA9IHBhc3M7XG4gICAgcGFzcyA9ICcnO1xuICB9XG5cbiAgaWYgKCFvcHRpb25zKSB7XG4gICAgb3B0aW9ucyA9IHtcbiAgICAgIHR5cGU6IHR5cGVvZiBidG9hID09PSAnZnVuY3Rpb24nID8gJ2Jhc2ljJyA6ICdhdXRvJ1xuICAgIH07XG4gIH1cblxuICBjb25zdCBlbmNvZGVyID0gc3RyaW5nID0+IHtcbiAgICBpZiAodHlwZW9mIGJ0b2EgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIHJldHVybiBidG9hKHN0cmluZyk7XG4gICAgfVxuXG4gICAgdGhyb3cgbmV3IEVycm9yKCdDYW5ub3QgdXNlIGJhc2ljIGF1dGgsIGJ0b2EgaXMgbm90IGEgZnVuY3Rpb24nKTtcbiAgfTtcblxuICByZXR1cm4gdGhpcy5fYXV0aCh1c2VyLCBwYXNzLCBvcHRpb25zLCBlbmNvZGVyKTtcbn07XG5cbi8qKlxuICogQWRkIHF1ZXJ5LXN0cmluZyBgdmFsYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIHJlcXVlc3QuZ2V0KCcvc2hvZXMnKVxuICogICAgIC5xdWVyeSgnc2l6ZT0xMCcpXG4gKiAgICAgLnF1ZXJ5KHsgY29sb3I6ICdibHVlJyB9KVxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fFN0cmluZ30gdmFsXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucXVlcnkgPSBmdW5jdGlvbih2YWwpIHtcbiAgaWYgKHR5cGVvZiB2YWwgIT09ICdzdHJpbmcnKSB2YWwgPSBzZXJpYWxpemUodmFsKTtcbiAgaWYgKHZhbCkgdGhpcy5fcXVlcnkucHVzaCh2YWwpO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUXVldWUgdGhlIGdpdmVuIGBmaWxlYCBhcyBhbiBhdHRhY2htZW50IHRvIHRoZSBzcGVjaWZpZWQgYGZpZWxkYCxcbiAqIHdpdGggb3B0aW9uYWwgYG9wdGlvbnNgIChvciBmaWxlbmFtZSkuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJy91cGxvYWQnKVxuICogICAuYXR0YWNoKCdjb250ZW50JywgbmV3IEJsb2IoWyc8YSBpZD1cImFcIj48YiBpZD1cImJcIj5oZXkhPC9iPjwvYT4nXSwgeyB0eXBlOiBcInRleHQvaHRtbFwifSkpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGZpZWxkXG4gKiBAcGFyYW0ge0Jsb2J8RmlsZX0gZmlsZVxuICogQHBhcmFtIHtTdHJpbmd8T2JqZWN0fSBvcHRpb25zXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYXR0YWNoID0gZnVuY3Rpb24oZmllbGQsIGZpbGUsIG9wdGlvbnMpIHtcbiAgaWYgKGZpbGUpIHtcbiAgICBpZiAodGhpcy5fZGF0YSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIHRoaXMuX2dldEZvcm1EYXRhKCkuYXBwZW5kKGZpZWxkLCBmaWxlLCBvcHRpb25zIHx8IGZpbGUubmFtZSk7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9nZXRGb3JtRGF0YSA9IGZ1bmN0aW9uKCkge1xuICBpZiAoIXRoaXMuX2Zvcm1EYXRhKSB7XG4gICAgdGhpcy5fZm9ybURhdGEgPSBuZXcgcm9vdC5Gb3JtRGF0YSgpO1xuICB9XG5cbiAgcmV0dXJuIHRoaXMuX2Zvcm1EYXRhO1xufTtcblxuLyoqXG4gKiBJbnZva2UgdGhlIGNhbGxiYWNrIHdpdGggYGVycmAgYW5kIGByZXNgXG4gKiBhbmQgaGFuZGxlIGFyaXR5IGNoZWNrLlxuICpcbiAqIEBwYXJhbSB7RXJyb3J9IGVyclxuICogQHBhcmFtIHtSZXNwb25zZX0gcmVzXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYWxsYmFjayA9IGZ1bmN0aW9uKGVyciwgcmVzKSB7XG4gIGlmICh0aGlzLl9zaG91bGRSZXRyeShlcnIsIHJlcykpIHtcbiAgICByZXR1cm4gdGhpcy5fcmV0cnkoKTtcbiAgfVxuXG4gIGNvbnN0IGZuID0gdGhpcy5fY2FsbGJhY2s7XG4gIHRoaXMuY2xlYXJUaW1lb3V0KCk7XG5cbiAgaWYgKGVycikge1xuICAgIGlmICh0aGlzLl9tYXhSZXRyaWVzKSBlcnIucmV0cmllcyA9IHRoaXMuX3JldHJpZXMgLSAxO1xuICAgIHRoaXMuZW1pdCgnZXJyb3InLCBlcnIpO1xuICB9XG5cbiAgZm4oZXJyLCByZXMpO1xufTtcblxuLyoqXG4gKiBJbnZva2UgY2FsbGJhY2sgd2l0aCB4LWRvbWFpbiBlcnJvci5cbiAqXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jcm9zc0RvbWFpbkVycm9yID0gZnVuY3Rpb24oKSB7XG4gIGNvbnN0IGVyciA9IG5ldyBFcnJvcihcbiAgICAnUmVxdWVzdCBoYXMgYmVlbiB0ZXJtaW5hdGVkXFxuUG9zc2libGUgY2F1c2VzOiB0aGUgbmV0d29yayBpcyBvZmZsaW5lLCBPcmlnaW4gaXMgbm90IGFsbG93ZWQgYnkgQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luLCB0aGUgcGFnZSBpcyBiZWluZyB1bmxvYWRlZCwgZXRjLidcbiAgKTtcbiAgZXJyLmNyb3NzRG9tYWluID0gdHJ1ZTtcblxuICBlcnIuc3RhdHVzID0gdGhpcy5zdGF0dXM7XG4gIGVyci5tZXRob2QgPSB0aGlzLm1ldGhvZDtcbiAgZXJyLnVybCA9IHRoaXMudXJsO1xuXG4gIHRoaXMuY2FsbGJhY2soZXJyKTtcbn07XG5cbi8vIFRoaXMgb25seSB3YXJucywgYmVjYXVzZSB0aGUgcmVxdWVzdCBpcyBzdGlsbCBsaWtlbHkgdG8gd29ya1xuUmVxdWVzdC5wcm90b3R5cGUuYWdlbnQgPSBmdW5jdGlvbigpIHtcbiAgY29uc29sZS53YXJuKCdUaGlzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gYnJvd3NlciB2ZXJzaW9uIG9mIHN1cGVyYWdlbnQnKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYSA9IFJlcXVlc3QucHJvdG90eXBlLmFnZW50O1xuUmVxdWVzdC5wcm90b3R5cGUuYnVmZmVyID0gUmVxdWVzdC5wcm90b3R5cGUuY2E7XG5cbi8vIFRoaXMgdGhyb3dzLCBiZWNhdXNlIGl0IGNhbid0IHNlbmQvcmVjZWl2ZSBkYXRhIGFzIGV4cGVjdGVkXG5SZXF1ZXN0LnByb3RvdHlwZS53cml0ZSA9ICgpID0+IHtcbiAgdGhyb3cgbmV3IEVycm9yKFxuICAgICdTdHJlYW1pbmcgaXMgbm90IHN1cHBvcnRlZCBpbiBicm93c2VyIHZlcnNpb24gb2Ygc3VwZXJhZ2VudCdcbiAgKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnBpcGUgPSBSZXF1ZXN0LnByb3RvdHlwZS53cml0ZTtcblxuLyoqXG4gKiBDaGVjayBpZiBgb2JqYCBpcyBhIGhvc3Qgb2JqZWN0LFxuICogd2UgZG9uJ3Qgd2FudCB0byBzZXJpYWxpemUgdGhlc2UgOilcbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqIGhvc3Qgb2JqZWN0XG4gKiBAcmV0dXJuIHtCb29sZWFufSBpcyBhIGhvc3Qgb2JqZWN0XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuUmVxdWVzdC5wcm90b3R5cGUuX2lzSG9zdCA9IGZ1bmN0aW9uKG9iaikge1xuICAvLyBOYXRpdmUgb2JqZWN0cyBzdHJpbmdpZnkgdG8gW29iamVjdCBGaWxlXSwgW29iamVjdCBCbG9iXSwgW29iamVjdCBGb3JtRGF0YV0sIGV0Yy5cbiAgcmV0dXJuIChcbiAgICBvYmogJiZcbiAgICB0eXBlb2Ygb2JqID09PSAnb2JqZWN0JyAmJlxuICAgICFBcnJheS5pc0FycmF5KG9iaikgJiZcbiAgICBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwob2JqKSAhPT0gJ1tvYmplY3QgT2JqZWN0XSdcbiAgKTtcbn07XG5cbi8qKlxuICogSW5pdGlhdGUgcmVxdWVzdCwgaW52b2tpbmcgY2FsbGJhY2sgYGZuKHJlcylgXG4gKiB3aXRoIGFuIGluc3RhbmNlb2YgYFJlc3BvbnNlYC5cbiAqXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBmblxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmVuZCA9IGZ1bmN0aW9uKGZuKSB7XG4gIGlmICh0aGlzLl9lbmRDYWxsZWQpIHtcbiAgICBjb25zb2xlLndhcm4oXG4gICAgICAnV2FybmluZzogLmVuZCgpIHdhcyBjYWxsZWQgdHdpY2UuIFRoaXMgaXMgbm90IHN1cHBvcnRlZCBpbiBzdXBlcmFnZW50J1xuICAgICk7XG4gIH1cblxuICB0aGlzLl9lbmRDYWxsZWQgPSB0cnVlO1xuXG4gIC8vIHN0b3JlIGNhbGxiYWNrXG4gIHRoaXMuX2NhbGxiYWNrID0gZm4gfHwgbm9vcDtcblxuICAvLyBxdWVyeXN0cmluZ1xuICB0aGlzLl9maW5hbGl6ZVF1ZXJ5U3RyaW5nKCk7XG5cbiAgdGhpcy5fZW5kKCk7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fc2V0VXBsb2FkVGltZW91dCA9IGZ1bmN0aW9uKCkge1xuICBjb25zdCBzZWxmID0gdGhpcztcblxuICAvLyB1cGxvYWQgdGltZW91dCBpdCdzIHdva3JzIG9ubHkgaWYgZGVhZGxpbmUgdGltZW91dCBpcyBvZmZcbiAgaWYgKHRoaXMuX3VwbG9hZFRpbWVvdXQgJiYgIXRoaXMuX3VwbG9hZFRpbWVvdXRUaW1lcikge1xuICAgIHRoaXMuX3VwbG9hZFRpbWVvdXRUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgc2VsZi5fdGltZW91dEVycm9yKFxuICAgICAgICAnVXBsb2FkIHRpbWVvdXQgb2YgJyxcbiAgICAgICAgc2VsZi5fdXBsb2FkVGltZW91dCxcbiAgICAgICAgJ0VUSU1FRE9VVCdcbiAgICAgICk7XG4gICAgfSwgdGhpcy5fdXBsb2FkVGltZW91dCk7XG4gIH1cbn07XG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG5SZXF1ZXN0LnByb3RvdHlwZS5fZW5kID0gZnVuY3Rpb24oKSB7XG4gIGlmICh0aGlzLl9hYm9ydGVkKVxuICAgIHJldHVybiB0aGlzLmNhbGxiYWNrKFxuICAgICAgbmV3IEVycm9yKCdUaGUgcmVxdWVzdCBoYXMgYmVlbiBhYm9ydGVkIGV2ZW4gYmVmb3JlIC5lbmQoKSB3YXMgY2FsbGVkJylcbiAgICApO1xuXG4gIGNvbnN0IHNlbGYgPSB0aGlzO1xuICB0aGlzLnhociA9IHJlcXVlc3QuZ2V0WEhSKCk7XG4gIGNvbnN0IHsgeGhyIH0gPSB0aGlzO1xuICBsZXQgZGF0YSA9IHRoaXMuX2Zvcm1EYXRhIHx8IHRoaXMuX2RhdGE7XG5cbiAgdGhpcy5fc2V0VGltZW91dHMoKTtcblxuICAvLyBzdGF0ZSBjaGFuZ2VcbiAgeGhyLm9ucmVhZHlzdGF0ZWNoYW5nZSA9ICgpID0+IHtcbiAgICBjb25zdCB7IHJlYWR5U3RhdGUgfSA9IHhocjtcbiAgICBpZiAocmVhZHlTdGF0ZSA+PSAyICYmIHNlbGYuX3Jlc3BvbnNlVGltZW91dFRpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQoc2VsZi5fcmVzcG9uc2VUaW1lb3V0VGltZXIpO1xuICAgIH1cblxuICAgIGlmIChyZWFkeVN0YXRlICE9PSA0KSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gSW4gSUU5LCByZWFkcyB0byBhbnkgcHJvcGVydHkgKGUuZy4gc3RhdHVzKSBvZmYgb2YgYW4gYWJvcnRlZCBYSFIgd2lsbFxuICAgIC8vIHJlc3VsdCBpbiB0aGUgZXJyb3IgXCJDb3VsZCBub3QgY29tcGxldGUgdGhlIG9wZXJhdGlvbiBkdWUgdG8gZXJyb3IgYzAwYzAyM2ZcIlxuICAgIGxldCBzdGF0dXM7XG4gICAgdHJ5IHtcbiAgICAgIHN0YXR1cyA9IHhoci5zdGF0dXM7XG4gICAgfSBjYXRjaCB7XG4gICAgICBzdGF0dXMgPSAwO1xuICAgIH1cblxuICAgIGlmICghc3RhdHVzKSB7XG4gICAgICBpZiAoc2VsZi50aW1lZG91dCB8fCBzZWxmLl9hYm9ydGVkKSByZXR1cm47XG4gICAgICByZXR1cm4gc2VsZi5jcm9zc0RvbWFpbkVycm9yKCk7XG4gICAgfVxuXG4gICAgc2VsZi5lbWl0KCdlbmQnKTtcbiAgfTtcblxuICAvLyBwcm9ncmVzc1xuICBjb25zdCBoYW5kbGVQcm9ncmVzcyA9IChkaXJlY3Rpb24sIGUpID0+IHtcbiAgICBpZiAoZS50b3RhbCA+IDApIHtcbiAgICAgIGUucGVyY2VudCA9IChlLmxvYWRlZCAvIGUudG90YWwpICogMTAwO1xuXG4gICAgICBpZiAoZS5wZXJjZW50ID09PSAxMDApIHtcbiAgICAgICAgY2xlYXJUaW1lb3V0KHNlbGYuX3VwbG9hZFRpbWVvdXRUaW1lcik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZS5kaXJlY3Rpb24gPSBkaXJlY3Rpb247XG4gICAgc2VsZi5lbWl0KCdwcm9ncmVzcycsIGUpO1xuICB9O1xuXG4gIGlmICh0aGlzLmhhc0xpc3RlbmVycygncHJvZ3Jlc3MnKSkge1xuICAgIHRyeSB7XG4gICAgICB4aHIuYWRkRXZlbnRMaXN0ZW5lcigncHJvZ3Jlc3MnLCBoYW5kbGVQcm9ncmVzcy5iaW5kKG51bGwsICdkb3dubG9hZCcpKTtcbiAgICAgIGlmICh4aHIudXBsb2FkKSB7XG4gICAgICAgIHhoci51cGxvYWQuYWRkRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgICAncHJvZ3Jlc3MnLFxuICAgICAgICAgIGhhbmRsZVByb2dyZXNzLmJpbmQobnVsbCwgJ3VwbG9hZCcpXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBBY2Nlc3NpbmcgeGhyLnVwbG9hZCBmYWlscyBpbiBJRSBmcm9tIGEgd2ViIHdvcmtlciwgc28ganVzdCBwcmV0ZW5kIGl0IGRvZXNuJ3QgZXhpc3QuXG4gICAgICAvLyBSZXBvcnRlZCBoZXJlOlxuICAgICAgLy8gaHR0cHM6Ly9jb25uZWN0Lm1pY3Jvc29mdC5jb20vSUUvZmVlZGJhY2svZGV0YWlscy84MzcyNDUveG1saHR0cHJlcXVlc3QtdXBsb2FkLXRocm93cy1pbnZhbGlkLWFyZ3VtZW50LXdoZW4tdXNlZC1mcm9tLXdlYi13b3JrZXItY29udGV4dFxuICAgIH1cbiAgfVxuXG4gIGlmICh4aHIudXBsb2FkKSB7XG4gICAgdGhpcy5fc2V0VXBsb2FkVGltZW91dCgpO1xuICB9XG5cbiAgLy8gaW5pdGlhdGUgcmVxdWVzdFxuICB0cnkge1xuICAgIGlmICh0aGlzLnVzZXJuYW1lICYmIHRoaXMucGFzc3dvcmQpIHtcbiAgICAgIHhoci5vcGVuKHRoaXMubWV0aG9kLCB0aGlzLnVybCwgdHJ1ZSwgdGhpcy51c2VybmFtZSwgdGhpcy5wYXNzd29yZCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHhoci5vcGVuKHRoaXMubWV0aG9kLCB0aGlzLnVybCwgdHJ1ZSk7XG4gICAgfVxuICB9IGNhdGNoIChlcnIpIHtcbiAgICAvLyBzZWUgIzExNDlcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhlcnIpO1xuICB9XG5cbiAgLy8gQ09SU1xuICBpZiAodGhpcy5fd2l0aENyZWRlbnRpYWxzKSB4aHIud2l0aENyZWRlbnRpYWxzID0gdHJ1ZTtcblxuICAvLyBib2R5XG4gIGlmIChcbiAgICAhdGhpcy5fZm9ybURhdGEgJiZcbiAgICB0aGlzLm1ldGhvZCAhPT0gJ0dFVCcgJiZcbiAgICB0aGlzLm1ldGhvZCAhPT0gJ0hFQUQnICYmXG4gICAgdHlwZW9mIGRhdGEgIT09ICdzdHJpbmcnICYmXG4gICAgIXRoaXMuX2lzSG9zdChkYXRhKVxuICApIHtcbiAgICAvLyBzZXJpYWxpemUgc3R1ZmZcbiAgICBjb25zdCBjb250ZW50VHlwZSA9IHRoaXMuX2hlYWRlclsnY29udGVudC10eXBlJ107XG4gICAgbGV0IHNlcmlhbGl6ZSA9XG4gICAgICB0aGlzLl9zZXJpYWxpemVyIHx8XG4gICAgICByZXF1ZXN0LnNlcmlhbGl6ZVtjb250ZW50VHlwZSA/IGNvbnRlbnRUeXBlLnNwbGl0KCc7JylbMF0gOiAnJ107XG4gICAgaWYgKCFzZXJpYWxpemUgJiYgaXNKU09OKGNvbnRlbnRUeXBlKSkge1xuICAgICAgc2VyaWFsaXplID0gcmVxdWVzdC5zZXJpYWxpemVbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICB9XG5cbiAgICBpZiAoc2VyaWFsaXplKSBkYXRhID0gc2VyaWFsaXplKGRhdGEpO1xuICB9XG5cbiAgLy8gc2V0IGhlYWRlciBmaWVsZHNcbiAgZm9yIChjb25zdCBmaWVsZCBpbiB0aGlzLmhlYWRlcikge1xuICAgIGlmICh0aGlzLmhlYWRlcltmaWVsZF0gPT09IG51bGwpIGNvbnRpbnVlO1xuXG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbCh0aGlzLmhlYWRlciwgZmllbGQpKVxuICAgICAgeGhyLnNldFJlcXVlc3RIZWFkZXIoZmllbGQsIHRoaXMuaGVhZGVyW2ZpZWxkXSk7XG4gIH1cblxuICBpZiAodGhpcy5fcmVzcG9uc2VUeXBlKSB7XG4gICAgeGhyLnJlc3BvbnNlVHlwZSA9IHRoaXMuX3Jlc3BvbnNlVHlwZTtcbiAgfVxuXG4gIC8vIHNlbmQgc3R1ZmZcbiAgdGhpcy5lbWl0KCdyZXF1ZXN0JywgdGhpcyk7XG5cbiAgLy8gSUUxMSB4aHIuc2VuZCh1bmRlZmluZWQpIHNlbmRzICd1bmRlZmluZWQnIHN0cmluZyBhcyBQT1NUIHBheWxvYWQgKGluc3RlYWQgb2Ygbm90aGluZylcbiAgLy8gV2UgbmVlZCBudWxsIGhlcmUgaWYgZGF0YSBpcyB1bmRlZmluZWRcbiAgeGhyLnNlbmQodHlwZW9mIGRhdGEgPT09ICd1bmRlZmluZWQnID8gbnVsbCA6IGRhdGEpO1xufTtcblxucmVxdWVzdC5hZ2VudCA9ICgpID0+IG5ldyBBZ2VudCgpO1xuXG5bJ0dFVCcsICdQT1NUJywgJ09QVElPTlMnLCAnUEFUQ0gnLCAnUFVUJywgJ0RFTEVURSddLmZvckVhY2gobWV0aG9kID0+IHtcbiAgQWdlbnQucHJvdG90eXBlW21ldGhvZC50b0xvd2VyQ2FzZSgpXSA9IGZ1bmN0aW9uKHVybCwgZm4pIHtcbiAgICBjb25zdCByZXEgPSBuZXcgcmVxdWVzdC5SZXF1ZXN0KG1ldGhvZCwgdXJsKTtcbiAgICB0aGlzLl9zZXREZWZhdWx0cyhyZXEpO1xuICAgIGlmIChmbikge1xuICAgICAgcmVxLmVuZChmbik7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcTtcbiAgfTtcbn0pO1xuXG5BZ2VudC5wcm90b3R5cGUuZGVsID0gQWdlbnQucHJvdG90eXBlLmRlbGV0ZTtcblxuLyoqXG4gKiBHRVQgYHVybGAgd2l0aCBvcHRpb25hbCBjYWxsYmFjayBgZm4ocmVzKWAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVybFxuICogQHBhcmFtIHtNaXhlZHxGdW5jdGlvbn0gW2RhdGFdIG9yIGZuXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbZm5dXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5yZXF1ZXN0LmdldCA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gIGNvbnN0IHJlcSA9IHJlcXVlc3QoJ0dFVCcsIHVybCk7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIGZuID0gZGF0YTtcbiAgICBkYXRhID0gbnVsbDtcbiAgfVxuXG4gIGlmIChkYXRhKSByZXEucXVlcnkoZGF0YSk7XG4gIGlmIChmbikgcmVxLmVuZChmbik7XG4gIHJldHVybiByZXE7XG59O1xuXG4vKipcbiAqIEhFQUQgYHVybGAgd2l0aCBvcHRpb25hbCBjYWxsYmFjayBgZm4ocmVzKWAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVybFxuICogQHBhcmFtIHtNaXhlZHxGdW5jdGlvbn0gW2RhdGFdIG9yIGZuXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbZm5dXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5yZXF1ZXN0LmhlYWQgPSAodXJsLCBkYXRhLCBmbikgPT4ge1xuICBjb25zdCByZXEgPSByZXF1ZXN0KCdIRUFEJywgdXJsKTtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgZm4gPSBkYXRhO1xuICAgIGRhdGEgPSBudWxsO1xuICB9XG5cbiAgaWYgKGRhdGEpIHJlcS5xdWVyeShkYXRhKTtcbiAgaWYgKGZuKSByZXEuZW5kKGZuKTtcbiAgcmV0dXJuIHJlcTtcbn07XG5cbi8qKlxuICogT1BUSU9OUyBxdWVyeSB0byBgdXJsYCB3aXRoIG9wdGlvbmFsIGNhbGxiYWNrIGBmbihyZXMpYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdXJsXG4gKiBAcGFyYW0ge01peGVkfEZ1bmN0aW9ufSBbZGF0YV0gb3IgZm5cbiAqIEBwYXJhbSB7RnVuY3Rpb259IFtmbl1cbiAqIEByZXR1cm4ge1JlcXVlc3R9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbnJlcXVlc3Qub3B0aW9ucyA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gIGNvbnN0IHJlcSA9IHJlcXVlc3QoJ09QVElPTlMnLCB1cmwpO1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdmdW5jdGlvbicpIHtcbiAgICBmbiA9IGRhdGE7XG4gICAgZGF0YSA9IG51bGw7XG4gIH1cblxuICBpZiAoZGF0YSkgcmVxLnNlbmQoZGF0YSk7XG4gIGlmIChmbikgcmVxLmVuZChmbik7XG4gIHJldHVybiByZXE7XG59O1xuXG4vKipcbiAqIERFTEVURSBgdXJsYCB3aXRoIG9wdGlvbmFsIGBkYXRhYCBhbmQgY2FsbGJhY2sgYGZuKHJlcylgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1cmxcbiAqIEBwYXJhbSB7TWl4ZWR9IFtkYXRhXVxuICogQHBhcmFtIHtGdW5jdGlvbn0gW2ZuXVxuICogQHJldHVybiB7UmVxdWVzdH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gZGVsKHVybCwgZGF0YSwgZm4pIHtcbiAgY29uc3QgcmVxID0gcmVxdWVzdCgnREVMRVRFJywgdXJsKTtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgZm4gPSBkYXRhO1xuICAgIGRhdGEgPSBudWxsO1xuICB9XG5cbiAgaWYgKGRhdGEpIHJlcS5zZW5kKGRhdGEpO1xuICBpZiAoZm4pIHJlcS5lbmQoZm4pO1xuICByZXR1cm4gcmVxO1xufVxuXG5yZXF1ZXN0LmRlbCA9IGRlbDtcbnJlcXVlc3QuZGVsZXRlID0gZGVsO1xuXG4vKipcbiAqIFBBVENIIGB1cmxgIHdpdGggb3B0aW9uYWwgYGRhdGFgIGFuZCBjYWxsYmFjayBgZm4ocmVzKWAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVybFxuICogQHBhcmFtIHtNaXhlZH0gW2RhdGFdXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbZm5dXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5yZXF1ZXN0LnBhdGNoID0gKHVybCwgZGF0YSwgZm4pID0+IHtcbiAgY29uc3QgcmVxID0gcmVxdWVzdCgnUEFUQ0gnLCB1cmwpO1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdmdW5jdGlvbicpIHtcbiAgICBmbiA9IGRhdGE7XG4gICAgZGF0YSA9IG51bGw7XG4gIH1cblxuICBpZiAoZGF0YSkgcmVxLnNlbmQoZGF0YSk7XG4gIGlmIChmbikgcmVxLmVuZChmbik7XG4gIHJldHVybiByZXE7XG59O1xuXG4vKipcbiAqIFBPU1QgYHVybGAgd2l0aCBvcHRpb25hbCBgZGF0YWAgYW5kIGNhbGxiYWNrIGBmbihyZXMpYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdXJsXG4gKiBAcGFyYW0ge01peGVkfSBbZGF0YV1cbiAqIEBwYXJhbSB7RnVuY3Rpb259IFtmbl1cbiAqIEByZXR1cm4ge1JlcXVlc3R9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbnJlcXVlc3QucG9zdCA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gIGNvbnN0IHJlcSA9IHJlcXVlc3QoJ1BPU1QnLCB1cmwpO1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdmdW5jdGlvbicpIHtcbiAgICBmbiA9IGRhdGE7XG4gICAgZGF0YSA9IG51bGw7XG4gIH1cblxuICBpZiAoZGF0YSkgcmVxLnNlbmQoZGF0YSk7XG4gIGlmIChmbikgcmVxLmVuZChmbik7XG4gIHJldHVybiByZXE7XG59O1xuXG4vKipcbiAqIFBVVCBgdXJsYCB3aXRoIG9wdGlvbmFsIGBkYXRhYCBhbmQgY2FsbGJhY2sgYGZuKHJlcylgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1cmxcbiAqIEBwYXJhbSB7TWl4ZWR8RnVuY3Rpb259IFtkYXRhXSBvciBmblxuICogQHBhcmFtIHtGdW5jdGlvbn0gW2ZuXVxuICogQHJldHVybiB7UmVxdWVzdH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxucmVxdWVzdC5wdXQgPSAodXJsLCBkYXRhLCBmbikgPT4ge1xuICBjb25zdCByZXEgPSByZXF1ZXN0KCdQVVQnLCB1cmwpO1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdmdW5jdGlvbicpIHtcbiAgICBmbiA9IGRhdGE7XG4gICAgZGF0YSA9IG51bGw7XG4gIH1cblxuICBpZiAoZGF0YSkgcmVxLnNlbmQoZGF0YSk7XG4gIGlmIChmbikgcmVxLmVuZChmbik7XG4gIHJldHVybiByZXE7XG59O1xuIl19