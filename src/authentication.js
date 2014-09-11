var crypto = require('crypto');

// Bytesize
var len = 128;

// Current prefered algorithm
var currentAlgorithm = 'pbkdf2';

// Rounds of encryption
var currentIterations = 12000;

// root of hashing algorithm type hierarchy
var HashAlgorithm = function() {
};
HashAlgorithm.prototype = {
    name : '',
    adaptive : false,
    doHash : function(hashArgs) {
        throw "Algorithm not defined!";
    }
};

// non-iterative hash functions supported by crypto
var SimpleHashAlgorithm = function(name) {
    this.name = name;
};
SimpleHashAlgorithm.prototype = Object.create(HashAlgorithm.prototype, {
    doHash : {
        value : function(hashArgs, fn) {
            var hash;
            hash = crypto.createHash(this.name).update(
                    hashArgs.plaintext + hashArgs.salt).digest('base64');
            fn(null, this.name + "$" + hash + '$' + hashArgs.salt);
        }
    }
});

// adaptive algorithm - need name + iterations
var AdaptiveHashAlgorithm = function(name, hashFunction) {
    this.name = name;
    this.doHash = hashFunction;
};
AdaptiveHashAlgorithm.prototype = Object.create(HashAlgorithm.prototype, {
    adaptive : {
        value : true
    }
});

// This is an example of how to secure an obsolete hash with a wrapper adaptive
// algorithm. If both wrapper and wrapped algorithms are adaptive of course you
// will need to have a composite iteration field as well
var WrappedHashAlgorithm = function(name, wrappedAlgorithm, wrapperAlgorithm) {
    this.name = name;
    this.wrappedAlgorithm = wrappedAlgorithm;
    this.wrapperAlgorithm = wrapperAlgorithm;
};
WrappedHashAlgorithm.prototype = Object
        .create(AdaptiveHashAlgorithm.prototype,
                {
                    wrappedAlgorithm : {
                        value : undefined
                    },
                    wrapperAlgorithm : {
                        value : undefined
                    },
                    doHash : {
                        value : function(hashArgs, fn) {
                            // 1st salt is for wrapped algorithm, 2nd for
                            // wrapper
                            var salts = hashArgs.salt.split('|');
                            var wrapperAlgorithm = this.wrapperAlgorithm;
                            var name = this.name;

                            var wrapHash = function(err, hash) {
                                if (err)
                                    return fn(err);
                                fn(null, wrapperAlgorithm.name + '$'
                                        + hashArgs.iterations + '$'
                                        + hash.toString('base64') + '$'
                                        + hashArgs.salt);
                            };

                            // create wrapped hash with plaintext password
                            this.wrappedAlgorithm.doHash({
                                plaintext : hashArgs.plaintext,
                                salt : salts[0]
                            }, wrapHash);
                        }
                    }
                });

// lookup table for the algorithms we support
var algorithms = {
    sha1 : new SimpleHashAlgorithm('sha1'),
    sha256 : new SimpleHashAlgorithm('sha256'),
    pbkdf2 : new AdaptiveHashAlgorithm('pbkdf2', function(hashArgs, fn) {
        // use crypto.pbkdf2 to generate hash
        var onHash = function(err, hash) {
            if (err)
                return fn(err);
            fn(null, 'pbkdf2$' + hashArgs.iterations + '$'
                    + hash.toString('base64') + '$' + hashArgs.salt);
        };

        crypto.pbkdf2(hashArgs.plaintext, hashArgs.salt, hashArgs.iterations,
                hashArgs.byteLen, onHash);
    })
};
//here's how to wrap an obsolete hash
algorithms.sha1topbkdf2 = new WrappedHashAlgorithm('sha1topbkdf2',
        algorithms.sha1, algorithms.pbkdf2);

// helper function to make secured credentials more readable
exports.splitCredentialFields = function(hash) {
    // 3 fields for simple hash, 4 for adaptive
    var fields = hash.split('$');
    if (fields.length < 3 || fields.length > 4)
        throw new Error('Hash should have 3 or 4 fields');
    if (fields.length === 3) {
        return {
            algorithm : fields[0],
            hash : fields[1],
            salt : fields[2]
        };
    } else {
        return {
            algorithm : fields[0],
            iterations : fields[1],
            hash : fields[2],
            salt : fields[3]
        };
    }
};

// Generate password hash with salt. If no salt provided, automatically
// generates it
exports.hash = function(password, salt, fn) {
    if (salt !== undefined && arguments.length === 3) {
        algorithms[currentAlgorithm].doHash({
            plaintext : password,
            salt : salt,
            iterations : currentIterations,
            byteLen : len
        }, fn);
    } else {
        // no salt provided - generate and recursively call same function
        if (typeof salt === 'function') {
            fn = salt;
        }
        crypto.randomBytes(len, function(err, genSalt) {
            if (err) {
                return fn(err);
            }
            genSalt = genSalt.toString('base64');
            exports.hash(password, genSalt, fn);
        });
    }
};

// verify password against secured credential using the algorithm, salt,
// iterations specified in the credential. If the credential is not using
// the current hash, re-hash and return the result
exports.verify = function(password, secureCredential, fn) {
    var fields, hashArgs, algorithm;
    // split and grab salt
    fields = exports.splitCredentialFields(secureCredential);
    algorithm = algorithms[fields.algorithm];
    if (algorithm === undefined) {
        return callback('Unsupported algorithm ' + fields[0]);
    }

    hashArgs = {
        plaintext : password,
        salt : fields.salt,
        byteLen : new Buffer(fields.hash, 'base64').length
    };
    if (fields.iterations) {
        hashArgs.iterations = parseInt(fields.iterations);
    }

    // delegate to algorithm implementation for actual hashing
    algorithm.doHash(hashArgs, function(err, calcHash) {
        if (err)
            return fn(err);
        if (calcHash !== secureCredential) {
            console.log('\n\n\ncalcHash        : ' + calcHash);
            console.log('\nsecureCredential: ' + secureCredential);
            fn(null, false);
        } else {
            if (fields.algorithm === currentAlgorithm
                    && fields.iterations === currentIterations) {
                fn(null, true);
            } else {
                // is obsolete algorithm
                exports.hash(password, function(err, reash) {
                    fn(null, true, reash)
                });
            }
        }

    });
};

// wrap hash with pbkdf2 algorithm. because there is a wrapped and wrapper
// algorithm, we need to output both salts; using pipe ('|') as separator.
exports.wrapSha1 = function(hashToWrap, fn) {
    var wrappedFields = exports.splitCredentialFields(hashToWrap);
    crypto.randomBytes(len, function(err, genSalt) {
        if (err)
            return fn(err);

        genSalt = genSalt.toString('base64');
        algorithms.pbkdf2.doHash({
            plaintext : hashToWrap,
            salt : genSalt,
            byteLen : len,
            iterations : currentIterations
        }, function(err, result) {
            if (err)
                return fn(err);
            var wrapperFields = exports.splitCredentialFields(result);
            // assemble final output
            fn(null, algorithms.sha1topbkdf2.name + '$'
                    + wrapperFields.iterations + '$' + wrapperFields.hash + '$'
                    + wrappedFields.salt + '|' + wrapperFields.salt);
        });
    });

};

// can change these if not in production to allow various scenarios to be tested
if (process.env.NODE_ENV !== 'production') {
    exports.setAlgorithm = function(newAlgorithm) {
        currentAlgorithm = newAlgorithm;
    }
    exports.setIterations = function(newIterations) {
        currentIterations = newIterations;
    }
    exports.setLen = function(newLen) {
        len = newLen;
    }
}