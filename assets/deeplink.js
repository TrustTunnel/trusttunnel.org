/*
 * TrustTunnel deep-link codec.
 *
 * Implements DEEP_LINK.md format version 2:
 *   tt://?<base64url(TLV fields)>
 *
 * The module has no DOM dependencies. It works in a browser as
 * window.TrustTunnelDeepLink and in Node.js through module.exports.
 */
(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.TrustTunnelDeepLink = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var SUPPORTED_VERSION = 2;

    var PROTOCOL_HTTP2 = 1;
    var PROTOCOL_HTTP3 = 2;
    var PROTOCOL_NAMES = {
        1: 'HTTP/2',
        2: 'HTTP/3'
    };
    var PROTOCOL_VALUES = {
        'http2': PROTOCOL_HTTP2,
        'http/2': PROTOCOL_HTTP2,
        'HTTP/2': PROTOCOL_HTTP2,
        'http3': PROTOCOL_HTTP3,
        'http/3': PROTOCOL_HTTP3,
        'HTTP/3': PROTOCOL_HTTP3
    };

    // --- Base64url (RFC 4648 section 5, no padding) ---
    function base64urlToBytes(str) {
        var b64 = String(str).replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4 !== 0) {
            b64 += '=';
        }
        var binary = atob(b64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function bytesToBase64url(bytes) {
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    // --- TLS varint (RFC 9000 section 16) ---
    function readVarint(buf, offset) {
        if (offset >= buf.length) {
            throw new Error('Unexpected end of buffer reading varint');
        }
        var first = buf[offset];
        var prefix = first >> 6;
        var len = 1 << prefix;
        if (offset + len > buf.length) {
            throw new Error('Unexpected end of buffer reading varint');
        }
        var value = first & 0x3f;
        for (var i = 1; i < len; i++) {
            value = value * 256 + buf[offset + i];
        }
        return { value: value, bytesRead: len };
    }

    function writeVarint(value) {
        if (value <= 0x3f) {
            return [value];
        } else if (value <= 0x3fff) {
            return [(value >> 8) | 0x40, value & 0xff];
        } else if (value <= 0x3fffffff) {
            return [
                (value >> 24) | 0x80,
                (value >> 16) & 0xff,
                (value >> 8) & 0xff,
                value & 0xff
            ];
        }
        throw new Error('Varint value too large');
    }

    // --- TLV helpers ---
    function stringToBytes(str) {
        return new TextEncoder().encode(str);
    }

    function writeTLV(tag, valueBytes) {
        var tagBytes = writeVarint(tag);
        var lenBytes = writeVarint(valueBytes.length);
        var result = new Uint8Array(tagBytes.length + lenBytes.length + valueBytes.length);
        result.set(tagBytes, 0);
        result.set(lenBytes, tagBytes.length);
        result.set(valueBytes, tagBytes.length + lenBytes.length);
        return result;
    }

    function writeTLVString(tag, str) {
        return writeTLV(tag, stringToBytes(str));
    }

    function writeTLVBool(tag, val) {
        return writeTLV(tag, new Uint8Array([val ? 0x01 : 0x00]));
    }

    // --- Client random validation (hex, optional mask) ---
    function validateClientRandomPrefix(value) {
        var parts = value.split('/');
        if (parts.length > 2) {
            return 'Client Random must have the form prefix or prefix/mask.';
        }
        if (!/^[0-9a-fA-F]+$/.test(parts[0])) {
            return 'The Client Random prefix must contain only hexadecimal characters.';
        }
        if (parts[0].length % 2 !== 0) {
            return 'The Client Random prefix must have an even number of characters.';
        }
        if (parts.length === 2) {
            if (!/^[0-9a-fA-F]*$/.test(parts[1])) {
                return 'The Client Random mask must contain only hexadecimal characters.';
            }
            if (parts[1].length % 2 !== 0) {
                return 'The Client Random mask must have an even number of characters.';
            }
        }
        return null;
    }

    function validateHexKey(value, label) {
        if (!/^[0-9a-fA-F]+$/.test(value)) {
            return label + ' must contain only hexadecimal characters.';
        }
        if (value.length % 2 !== 0) {
            return label + ' must have an even number of characters.';
        }
        return null;
    }

    function readBool(value, fieldName) {
        if (value.length !== 1 || (value[0] !== 0x00 && value[0] !== 0x01)) {
            throw new Error('Invalid ' + fieldName + ' value');
        }
        return value[0] === 0x01;
    }

    // --- Decode ---
    function extractPayload(input) {
        var value = String(input === null || input === undefined ? '' : input).trim();
        if (value.indexOf('tt://?') === 0) {
            return value.slice(6);
        }
        if (value.indexOf('tt://') === 0) {
            // Legacy format: tt://<base64url>, without the query marker.
            return value.slice(5);
        }
        if (value.indexOf('#tt=') === 0) {
            return value.slice(4);
        }
        if (value.indexOf('tt=') === 0) {
            return value.slice(3);
        }
        return value;
    }

    function parseTLV(bytes) {
        var config = {
            version: 0,
            name: null,
            hostname: null,
            addresses: [],
            custom_sni: null,
            has_ipv6: true,
            username: null,
            password: null,
            skip_verification: false,
            certificate_der: null,
            upstream_protocol: 'HTTP/2',
            anti_dpi: false,
            client_random_prefix: null,
            client_random_auth_key: null,
            tls_profile: null,
            subscription_url: null,
            dns_upstreams: []
        };

        var offset = 0;
        var decoder = new TextDecoder('utf-8');

        while (offset < bytes.length) {
            var tagResult = readVarint(bytes, offset);
            offset += tagResult.bytesRead;

            var lenResult = readVarint(bytes, offset);
            offset += lenResult.bytesRead;

            var tag = tagResult.value;
            var len = lenResult.value;

            if (offset + len > bytes.length) {
                throw new Error('TLV value exceeds buffer length');
            }

            var value = bytes.slice(offset, offset + len);
            offset += len;

            switch (tag) {
                case 0x00: // version
                    config.version = readVarint(value, 0).value;
                    if (config.version > SUPPORTED_VERSION) {
                        throw new Error('This link uses deep-link format version ' + config.version +
                            '. This page supports version ' + SUPPORTED_VERSION +
                            ' or lower. Download a newer version of this page.');
                    }
                    break;
                case 0x01: // hostname
                    config.hostname = decoder.decode(value);
                    break;
                case 0x02: // addresses (may repeat)
                    config.addresses.push(decoder.decode(value));
                    break;
                case 0x03: // custom_sni
                    config.custom_sni = decoder.decode(value);
                    break;
                case 0x04: // has_ipv6
                    config.has_ipv6 = readBool(value, 'has_ipv6');
                    break;
                case 0x05: // username
                    config.username = decoder.decode(value);
                    break;
                case 0x06: // password
                    config.password = decoder.decode(value);
                    break;
                case 0x07: // skip_verification
                    config.skip_verification = readBool(value, 'skip_verification');
                    break;
                case 0x08: // certificate (binary DER)
                    config.certificate_der = value.length > 0 ? value : null;
                    break;
                case 0x09: // upstream_protocol
                    if (value.length !== 1 || (value[0] !== PROTOCOL_HTTP2 && value[0] !== PROTOCOL_HTTP3)) {
                        throw new Error('Invalid upstream_protocol value');
                    }
                    config.upstream_protocol = PROTOCOL_NAMES[value[0]];
                    break;
                case 0x0A: // anti_dpi
                    config.anti_dpi = readBool(value, 'anti_dpi');
                    break;
                case 0x0B: // client_random_prefix
                    config.client_random_prefix = decoder.decode(value);
                    var prefixError = validateClientRandomPrefix(config.client_random_prefix);
                    if (prefixError) {
                        throw new Error('Invalid client_random_prefix: ' + prefixError);
                    }
                    break;
                case 0x0C: // name
                    config.name = decoder.decode(value);
                    break;
                case 0x0D: // dns_upstreams (String[]: varint length + UTF-8 bytes)
                    var dnsOffset = 0;
                    while (dnsOffset < value.length) {
                        var dnsLenResult = readVarint(value, dnsOffset);
                        dnsOffset += dnsLenResult.bytesRead;

                        if (dnsOffset + dnsLenResult.value > value.length) {
                            throw new Error('dns_upstreams entry exceeds buffer length');
                        }
                        var dnsEntry = decoder.decode(value.slice(dnsOffset, dnsOffset + dnsLenResult.value));
                        dnsOffset += dnsLenResult.value;
                        config.dns_upstreams.push(dnsEntry);
                    }
                    break;
                case 0x0E: // subscription_url
                    config.subscription_url = decoder.decode(value);
                    if (config.subscription_url.indexOf('https://') !== 0) {
                        throw new Error('The subscription URL must start with https://.');
                    }
                    break;
                case 0x0F: // client_random_auth_key
                    config.client_random_auth_key = decoder.decode(value);
                    var authKeyError = validateHexKey(config.client_random_auth_key, 'Client Random auth key');
                    if (authKeyError) {
                        throw new Error('Invalid client_random_auth_key: ' + authKeyError);
                    }
                    break;
                case 0x10: // tls_profile
                    config.tls_profile = decoder.decode(value) || null;
                    break;
                default:
                    // Unknown tags are ignored for forward compatibility.
                    break;
            }
        }

        // Static connection parameters are optional when a subscription URL is
        // present. They act as a fallback for the first connection attempt.
        if (!config.subscription_url) {
            if (!config.hostname) throw new Error('Missing required field: hostname');
            if (config.addresses.length === 0) throw new Error('Missing required field: addresses');
            if (!config.username) throw new Error('Missing required field: username');
            if (!config.password) throw new Error('Missing required field: password');
        }

        return config;
    }

    function decodePayload(payload) {
        if (!payload) {
            throw new Error('The link does not contain a TrustTunnel configuration payload.');
        }
        return parseTLV(base64urlToBytes(payload));
    }

    function decode(uri) {
        return decodePayload(extractPayload(uri));
    }

    // --- Encode ---
    function protocolValue(value) {
        if (value === undefined || value === null || value === '') {
            return PROTOCOL_HTTP2;
        }
        if (value === PROTOCOL_HTTP2 || value === PROTOCOL_HTTP3) {
            return value;
        }
        var resolved = PROTOCOL_VALUES[value];
        if (!resolved) {
            throw new Error('Unsupported upstream_protocol: ' + value);
        }
        return resolved;
    }

    function encodePayload(config) {
        config = config || {};

        var subscriptionUrl = config.subscription_url || null;
        if (subscriptionUrl && String(subscriptionUrl).indexOf('https://') !== 0) {
            throw new Error('The subscription URL must start with https://.');
        }

        var hostname = config.hostname || '';
        var username = config.username || '';
        var password = config.password || '';
        var addresses = config.addresses || [];

        if (!subscriptionUrl) {
            if (!hostname) throw new Error('Missing required field: hostname');
            if (addresses.length === 0) throw new Error('Missing required field: addresses');
            if (!username) throw new Error('Missing required field: username');
            if (!password) throw new Error('Missing required field: password');
        }

        var clientRandomPrefix = config.client_random_prefix || null;
        var clientRandomAuthKey = config.client_random_auth_key || null;
        var tlsProfile = config.tls_profile || null;
        if (clientRandomPrefix) {
            var prefixError = validateClientRandomPrefix(clientRandomPrefix);
            if (prefixError) throw new Error(prefixError);
        }
        if (clientRandomAuthKey) {
            var authKeyError = validateHexKey(clientRandomAuthKey, 'Client Random auth key');
            if (authKeyError) throw new Error(authKeyError);
        }

        var certificate = config.certificate_der || null;
        var protocol = protocolValue(config.upstream_protocol);
        var hasIpv6 = config.has_ipv6 !== false;
        var dnsUpstreams = config.dns_upstreams || [];
        var chunks = [];

        // Field order matches deeplink/src/encode.rs.
        chunks.push(writeTLV(0x00, new Uint8Array([SUPPORTED_VERSION])));
        if (hostname) chunks.push(writeTLVString(0x01, hostname));
        if (username) chunks.push(writeTLVString(0x05, username));
        if (password) chunks.push(writeTLVString(0x06, password));
        addresses.forEach(function (address) {
            chunks.push(writeTLVString(0x02, address));
        });
        if (clientRandomPrefix) chunks.push(writeTLVString(0x0B, clientRandomPrefix));
        if (clientRandomAuthKey) chunks.push(writeTLVString(0x0F, clientRandomAuthKey));
        if (tlsProfile && tlsProfile !== 'chrome') chunks.push(writeTLVString(0x10, tlsProfile));
        if (config.custom_sni) chunks.push(writeTLVString(0x03, config.custom_sni));
        if (!hasIpv6) chunks.push(writeTLVBool(0x04, false));
        if (config.skip_verification) chunks.push(writeTLVBool(0x07, true));
        if (config.anti_dpi) chunks.push(writeTLVBool(0x0A, true));
        if (certificate) chunks.push(writeTLV(0x08, certificate));
        if (protocol === PROTOCOL_HTTP3) {
            chunks.push(writeTLV(0x09, new Uint8Array([protocol])));
        }
        if (config.name) chunks.push(writeTLVString(0x0C, config.name));
        if (dnsUpstreams.length > 0) {
            var dnsChunks = [];
            var dnsLength = 0;
            dnsUpstreams.forEach(function (dns) {
                var dnsBytes = stringToBytes(dns);
                var dnsLenBytes = writeVarint(dnsBytes.length);
                dnsChunks.push({ len: dnsLenBytes, data: dnsBytes });
                dnsLength += dnsLenBytes.length + dnsBytes.length;
            });
            var dnsValue = new Uint8Array(dnsLength);
            var dnsOffset = 0;
            dnsChunks.forEach(function (chunk) {
                dnsValue.set(chunk.len, dnsOffset);
                dnsOffset += chunk.len.length;
                dnsValue.set(chunk.data, dnsOffset);
                dnsOffset += chunk.data.length;
            });
            chunks.push(writeTLV(0x0D, dnsValue));
        }
        if (subscriptionUrl) chunks.push(writeTLVString(0x0E, subscriptionUrl));

        var totalLength = 0;
        chunks.forEach(function (chunk) {
            totalLength += chunk.length;
        });
        var payload = new Uint8Array(totalLength);
        var offset = 0;
        chunks.forEach(function (chunk) {
            payload.set(chunk, offset);
            offset += chunk.length;
        });
        return bytesToBase64url(payload);
    }

    function encode(config) {
        return 'tt://?' + encodePayload(config);
    }

    // --- PEM / DER certificate helpers ---
    function pemToDer(pem) {
        var lines = String(pem).split('\n');
        var derChunks = [];
        var b64 = '';
        var inBlock = false;
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line === '-----BEGIN CERTIFICATE-----') {
                inBlock = true;
                b64 = '';
                continue;
            }
            if (line === '-----END CERTIFICATE-----') {
                inBlock = false;
                if (b64) {
                    var binary = atob(b64);
                    var bytes = new Uint8Array(binary.length);
                    for (var j = 0; j < binary.length; j++) {
                        bytes[j] = binary.charCodeAt(j);
                    }
                    derChunks.push(bytes);
                }
                b64 = '';
                continue;
            }
            if (inBlock && line.length > 0) {
                b64 += line;
            }
        }
        if (derChunks.length === 0) {
            throw new Error('No valid PEM certificate data found');
        }
        var totalLength = 0;
        derChunks.forEach(function (chunk) {
            totalLength += chunk.length;
        });
        var result = new Uint8Array(totalLength);
        var offset = 0;
        derChunks.forEach(function (chunk) {
            result.set(chunk, offset);
            offset += chunk.length;
        });
        return result;
    }

    function readAsn1Length(bytes, offset) {
        if (offset >= bytes.length) {
            throw new Error('Unexpected end of DER data');
        }
        var first = bytes[offset];
        if (first < 0x80) {
            return { length: first, next: offset + 1 };
        }
        var count = first & 0x7f;
        if (count === 0 || count > 4 || offset + 1 + count > bytes.length) {
            throw new Error('Invalid DER certificate length');
        }
        var length = 0;
        for (var i = 0; i < count; i++) {
            length = length * 256 + bytes[offset + 1 + i];
        }
        return { length: length, next: offset + 1 + count };
    }

    function derToPem(derBytes) {
        var certs = [];
        var offset = 0;
        while (offset < derBytes.length) {
            if (derBytes[offset] !== 0x30) {
                throw new Error('Invalid DER certificate data');
            }
            var lenResult = readAsn1Length(derBytes, offset + 1);
            var certEnd = lenResult.next + lenResult.length;
            if (certEnd > derBytes.length) {
                throw new Error('Invalid DER certificate length');
            }
            certs.push(derBytes.slice(offset, certEnd));
            offset = certEnd;
        }
        if (certs.length === 0) {
            throw new Error('No certificate data');
        }
        return certs.map(function (cert) {
            var binary = '';
            for (var i = 0; i < cert.length; i++) {
                binary += String.fromCharCode(cert[i]);
            }
            var lines = btoa(binary).match(/.{1,64}/g) || [];
            return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----';
        }).join('\n') + '\n';
    }

    return {
        SUPPORTED_VERSION: SUPPORTED_VERSION,
        decode: decode,
        decodePayload: decodePayload,
        encode: encode,
        encodePayload: encodePayload,
        encodeVarint: writeVarint,
        decodeVarint: readVarint,
        pemToDer: pemToDer,
        derToPem: derToPem,
        validateClientRandomPrefix: validateClientRandomPrefix,
        validateHexKey: validateHexKey
    };
});
