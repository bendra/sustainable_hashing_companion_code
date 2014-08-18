var crypto = require('crypto');

// Bytesize
var len = 128;

// Current prefered algorithm
var currentAlgorithm = 'pbkdf2';

// Rounds of encryption
var currentIterations = 12000;

// root of hashing algorithm type hierarchy
var hashAlgorithm = {
	name : '',
	adaptive : false,
	doHash : function(hashArgs) {
		throw "Algorithm not defined!";
	}
};

// non-iterative hash functions supported by crypto
var simpleHashAlgorithm = Object.create(hashAlgorithm, {
	doHash : {
		value : function(hashArgs, fn) {
			var hash;
			hash = crypto.createHash(this.name).update(
					hashArgs.plaintext + hashArgs.salt).digest('base64');
			fn(null, this.name + "$" + hash + '$'
					+ hashArgs.salt);
		}
	}
});

// This is an example of how to secure an obsolete hash with a wrapper adaptive
// algorithm. If both wrapper and wrapped algorithms are adaptive of course you
// will need to have a composite iteration field as well
var wrappedAlgorithm = Object.create(hashAlgorithm, {
	// assume wrapped algorithm is simple hash, outer is adaptive; if not you'd
	// have to split the iterations field as well
	wrappedAlgorithm : {
		value : ''
	},
	wrapperAlgorithm : {
		value : ''
	},
	adaptive : {
		value : true
	},
	doHash : {
		value : function(hashArgs, fn) {
			//1st salt is for wrapped algorithm, 2nd for wrapper
			var salts = hashArgs.salt.split('|');
			var wrapperAlgorithm = this.wrapperAlgorithm;
			var name = this.name;
			//create wrapped hash with plaintext password
			this.wrappedAlgorithm.doHash({
				plaintext : hashArgs.plaintext,
				salt : salts[0]
			}, function(err, wrappedHash) {
				//now treat the wrapped hash as plaintext to create the output hash
				wrapperAlgorithm.doHash({
					plaintext : wrappedHash,
					salt : salts[1],
					iterations : hashArgs.iterations
					}, function(err, wrapperHash) {
						if (err)
							return fn(err);
						var fields = exports
								.splitCredentialFields(wrapperHash);
						//callback with final output
						fn(null, name + '$' + hashArgs.iterations
								+ '$' + fields.hash + '$' + hashArgs.salt);
					});
			});
		}
	}
});

// lookup table for the algorithms we support
var algorithms = {
	sha1 : Object.create(simpleHashAlgorithm, {
		name : {
			value : 'sha1'
		}
	}),
	sha256 : Object.create(simpleHashAlgorithm, {
		name : {
			value : 'sha256'
		}
	}),
	pbkdf2 : Object.create(hashAlgorithm, {
		name : {
			value : 'pbkdf2'
		},
		adaptive : {
			value : false
		},
		doHash : {
			value : function(hashArgs, fn) {
				crypto.pbkdf2(hashArgs.plaintext, hashArgs.salt,
						hashArgs.iterations, len, function(err, hash) {
							if (err)
								return fn(err);
							fn(null, 'pbkdf2$' + hashArgs.iterations
									+ '$' + hash.toString('base64') + '$'
									+ hashArgs.salt);
						});
			}
		}
	})
};

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
			iterations : currentIterations
		}, fn);
	} else {
		//no salt provided - generate and recursively call same function
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
// iterations specified in the credential.  If the credential is not using
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
	};

	if (fields.iterations) {
		hashArgs.iterations = parseInt(fields.iterations);
	}

	//delegate to algorithm implementation for actual hashing
	algorithm.doHash(hashArgs, function(err, calcHash) {
		if(err)
			return fn(err);
		if(calcHash !== secureCredential)
			fn(null, false);
		else{
			if (fields.algorithm === currentAlgorithm
					&& fields.iterations === currentIterations) {
				fn(null, true);
			}else{
				//is obsolete algorithm
				exports.hash(password, function(err, reash){
					fn(null, true, reash)
				});
			}
		}
		
	});
};

// here's how to wrap an obsolete hash
algorithms.sha1topbkdf2 = Object.create(wrappedAlgorithm, {
	name : {
		value : 'sha1topbkdf2'
	},
	wrappedAlgorithm : {
		value : algorithms.sha1
	},
	wrapperAlgorithm : {
		value : algorithms.pbkdf2
	}
});

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
			iterations : currentIterations
		}, function(err, result) {
				if (err)
					return fn(err);
				var wrapperFields = exports.splitCredentialFields(result);
				fn(null, algorithms.sha1topbkdf2.name + '$'
						+ wrapperFields.iterations + '$' + wrapperFields.hash
						+ '$' + wrappedFields.salt + '|' + wrapperFields.salt);
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