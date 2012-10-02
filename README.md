# simple\_rsa\_encrypt 
[![Build Status](https://secure.travis-ci.org/paspao/simple_rsa_encrypt.png)](http://travis-ci.org/paspao/simple_rsa_encrypt)

This module provides access to RSA public-key encryption and  private-key decryption from OpenSSL.

## Install

	npm install simple_rsa_encrypt


## Build (from source)

	node-gyp clean && node-gyp configure && node-gyp -v build

## Usage

See test.js

```javascript

var simple_rsa_encrypt = require("simple_rsa_encrypt");


var rsa=new simple_rsa_encrypt.RsaEncrypter();

var mesg="Ciao Mondo...ops...Hello World!";

var encr=rsa.encrypt("-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0AFLLTkEOlTGvx9w/MEYr4Yji\n\
c5uy6J1A/6zTIxjZwFfREvFOJIBElbXfmZeoE2zshIqn+krnxNJUJsVZd8SCjcgI\n\
RxmFi5hMn6fL0GvrSo3MTs+xV18BmuR8XE6048tISoTfbPsFf6AxZhl3WJSOJj6k\n\
mo6I41CWwiJF0HL6rQIDAQAB\n\
-----END PUBLIC KEY-----",mesg);

console.log("\nNode encrypted\n"+encr);

var plainmesg=rsa.decrypt("-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQD0AFLLTkEOlTGvx9w/MEYr4Yjic5uy6J1A/6zTIxjZwFfREvFO\n\
JIBElbXfmZeoE2zshIqn+krnxNJUJsVZd8SCjcgIRxmFi5hMn6fL0GvrSo3MTs+x\n\
V18BmuR8XE6048tISoTfbPsFf6AxZhl3WJSOJj6kmo6I41CWwiJF0HL6rQIDAQAB\n\
AoGBAJ07BB8cKxHxk9X4zPUu71jheWqrIp60BHlZCA36JM5UgoIoWbSIEtufOVZ/\n\
y9kzw1HZytuZjuEw1HQDk9ImOkrAXHqTllmZ/BXj7qLrygq2XxzbFgvYhvYBpWI5\n\
KeYjPoptKberEsq6KFyusYLGF6FnPVamJn02oOWHDTdnquVFAkEA/Z08Fqlg5iuJ\n\
O3j/awme96m5cRHP8+4PuRfppN6DiJA9UqjkBULyVUXQ5EPerZWfXhHAEETvYjLJ\n\
Hl8b4cTj8wJBAPZL8DoPCVXXEMDPvJP1L99v49Y2o9B0FnY/Hpj7h53GJzyTe5df\n\
+PKyvgL4RIA7lcgtSyKE44stslZUSGmKbt8CQQCP3PmRAVPuPRQDoIeC+FossyJ2\n\
eVw1Sv2wSVhIJdEHTor6sMNoGKnOpWPxmG5gmVdlzTvd/rysP5LGn7z5PO7xAkA/\n\
slH1YfAjIBS4GMGHblCsM26z9ruU7IDmodpS7DIdjqKVGvtKocprUeisMfLdSwuo\n\
knYs/jsuwmmtw+xaRy/3AkB8ak0Fo/pcm9nvXNVDe5cK6Ku2cEqThihX5fjna8yi\n\
tQMVsY0MsC8Sy21y199wWQUBmAiV6rSuODrb8yQmYZ8w\n\
-----END RSA PRIVATE KEY-----",encr);

console.log("\nNode decrypted\n"+plainmesg);

```

```javascript

rsa.encrypt("-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0AFLLTkEOlTGvx9w/MEYr4Yji\n\
c5uy6J1A/6zTIxjZwFfREvFOJIBElbXfmZeoE2zshIqn+krnxNJUJsVZd8SCjcgI\n\
RxmFi5hMn6fL0GvrSo3MTs+xV18BmuR8XE6048tISoTfbPsFf6AxZhl3WJSOJj6k\n\
mo6I41CWwiJF0HL6rQIDAQAB\n\
-----END PUBLIC KEY-----",
	mesg,function(err,result){

		console.log('\nAsync Encrypt '+result);

rsa.decrypt("-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQD0AFLLTkEOlTGvx9w/MEYr4Yjic5uy6J1A/6zTIxjZwFfREvFO\n\
JIBElbXfmZeoE2zshIqn+krnxNJUJsVZd8SCjcgIRxmFi5hMn6fL0GvrSo3MTs+x\n\
V18BmuR8XE6048tISoTfbPsFf6AxZhl3WJSOJj6kmo6I41CWwiJF0HL6rQIDAQAB\n\
AoGBAJ07BB8cKxHxk9X4zPUu71jheWqrIp60BHlZCA36JM5UgoIoWbSIEtufOVZ/\n\
y9kzw1HZytuZjuEw1HQDk9ImOkrAXHqTllmZ/BXj7qLrygq2XxzbFgvYhvYBpWI5\n\
KeYjPoptKberEsq6KFyusYLGF6FnPVamJn02oOWHDTdnquVFAkEA/Z08Fqlg5iuJ\n\
O3j/awme96m5cRHP8+4PuRfppN6DiJA9UqjkBULyVUXQ5EPerZWfXhHAEETvYjLJ\n\
Hl8b4cTj8wJBAPZL8DoPCVXXEMDPvJP1L99v49Y2o9B0FnY/Hpj7h53GJzyTe5df\n\
+PKyvgL4RIA7lcgtSyKE44stslZUSGmKbt8CQQCP3PmRAVPuPRQDoIeC+FossyJ2\n\
eVw1Sv2wSVhIJdEHTor6sMNoGKnOpWPxmG5gmVdlzTvd/rysP5LGn7z5PO7xAkA/\n\
slH1YfAjIBS4GMGHblCsM26z9ruU7IDmodpS7DIdjqKVGvtKocprUeisMfLdSwuo\n\
knYs/jsuwmmtw+xaRy/3AkB8ak0Fo/pcm9nvXNVDe5cK6Ku2cEqThihX5fjna8yi\n\
tQMVsY0MsC8Sy21y199wWQUBmAiV6rSuODrb8yQmYZ8w\n\
-----END RSA PRIVATE KEY-----",
	result,function(err,res){

		console.log('\nAsync Decrypt '+res);

		assert.equal(mesg,res);
});

});

```

## Licence
Apache 2.0, see LICENCE file.