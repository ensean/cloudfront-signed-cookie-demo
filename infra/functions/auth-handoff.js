// CloudFront Function (viewer request, runtime cloudfront-js-2.0) on the static distribution.
//
// The main site signs the cookies but cannot set them: the static site is another host, and two
// *.cloudfront.net hosts share no cookie scope. After a login it redirects the browser here instead.
//
//   GET /_auth/set?p=<policy>&s=<signature>&k=<key pair id>&e=<expiry, unix s>&n=<path>
//       stores the four CloudFront signed cookies on THIS host and redirects to n.
//   GET /_auth/clear
//       deletes them and redirects to the signed-out page.
//
// The function never trusts the query: every value is checked against the narrow alphabet it can
// legitimately contain, so nothing can inject a header, an attribute or an off-site redirect.
// A forged request can only store cookies that CloudFront itself will refuse unless they carry a
// valid signature, so the function holds no secret.

var MAX_LIFETIME_SECONDS = 7 * 24 * 3600; // same bound as the signer's MaxTTL
var SIGNED_OUT_PATH = '/_public/signed-out.html';
var DEFAULT_PATH = '/index.html';

// CloudFront's base64 variant: + = / become - _ ~.
var TOKEN = /^[A-Za-z0-9_~\-]{1,2048}$/;
var KEY_ID = /^[A-Za-z0-9]{1,64}$/;
var EPOCH = /^[0-9]{1,12}$/;
// A local path: one leading slash, never "//", only URL-safe characters.
var LOCAL_PATH = /^\/(?!\/)[A-Za-z0-9._~%!$&'()*+,;=:@\/\-]{0,1024}$/;

var COOKIE_ATTRS = 'Path=/; Secure; HttpOnly; SameSite=Lax';

function param(request, name) {
  var q = request.querystring[name];
  if (!q || q.multiValue) {
    return null; // missing, or repeated (ambiguous)
  }
  return q.value;
}

function redirect(location, cookies) {
  var response = {
    statusCode: 303,
    statusDescription: 'See Other',
    headers: {
      location: { value: location },
      'cache-control': { value: 'no-store' },
      'referrer-policy': { value: 'no-referrer' },
    },
  };
  if (cookies) {
    response.cookies = cookies;
  }
  return response;
}

function bad(message) {
  return {
    statusCode: 400,
    statusDescription: 'Bad Request',
    headers: {
      'content-type': { value: 'text/plain; charset=utf-8' },
      'cache-control': { value: 'no-store' },
    },
    body: message + '\n',
  };
}

function safeNext(value) {
  if (value === null || !LOCAL_PATH.test(value)) {
    return DEFAULT_PATH;
  }
  // The public and auth areas are not destinations after a login.
  if (value.indexOf('/_auth/') === 0 || value.indexOf('/_public/') === 0) {
    return DEFAULT_PATH;
  }
  return value;
}

function setCookies(request) {
  var p = param(request, 'p');
  var s = param(request, 's');
  var k = param(request, 'k');
  var e = param(request, 'e');
  if (p === null || s === null || k === null || e === null) {
    return bad('missing parameter');
  }
  if (!TOKEN.test(p) || !TOKEN.test(s) || !KEY_ID.test(k) || !EPOCH.test(e)) {
    return bad('malformed parameter');
  }
  var expires = parseInt(e, 10);
  var now = Math.floor(Date.now() / 1000);
  if (expires <= now || expires > now + MAX_LIFETIME_SECONDS) {
    return bad('expiry out of range');
  }

  var attrs = COOKIE_ATTRS + '; Expires=' + new Date(expires * 1000).toUTCString();
  return redirect(safeNext(param(request, 'n')), {
    'CloudFront-Policy': { value: p, attributes: attrs },
    'CloudFront-Signature': { value: s, attributes: attrs },
    'CloudFront-Key-Pair-Id': { value: k, attributes: attrs },
    // Without this cookie CloudFront verifies with SHA-1 and rejects the SHA-256 signature.
    'CloudFront-Hash-Algorithm': { value: 'SHA256', attributes: attrs },
  });
}

function clearCookies() {
  var attrs = COOKIE_ATTRS + '; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  return redirect(SIGNED_OUT_PATH, {
    'CloudFront-Policy': { value: 'deleted', attributes: attrs },
    'CloudFront-Signature': { value: 'deleted', attributes: attrs },
    'CloudFront-Key-Pair-Id': { value: 'deleted', attributes: attrs },
    'CloudFront-Hash-Algorithm': { value: 'deleted', attributes: attrs },
  });
}

function handler(event) {
  var request = event.request;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return { statusCode: 405, statusDescription: 'Method Not Allowed', headers: { allow: { value: 'GET, HEAD' } } };
  }
  if (request.uri === '/_auth/set') {
    return setCookies(request);
  }
  if (request.uri === '/_auth/clear') {
    return clearCookies();
  }
  return { statusCode: 404, statusDescription: 'Not Found' };
}
