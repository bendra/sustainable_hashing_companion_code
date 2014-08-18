'use strict';

var authentication = require('../src/authentication');
var password1 = 'p@ssw0rd!1', password2 = 'p@ssw0rd!2', password3 = 'p@ssw0rd!3';
var sha1Hash, sha256Hash, pbkdf2Hash, pbkdf2Hash2, wrappedSha1Hash;
var readline = require('readline');
var rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
});

hashSha1();

function hashSha1() {
	console
			.log('Here we go!  Way back in 2000 you used Sha1 hashing with a \
20 byte salt...');

	authentication.setAlgorithm('sha1');
	authentication.setLen(20);

	authentication.hash(password1, function(err, result) {
		sha1Hash = result;
		console.log('\nFor plaintext ' + password1 + ', resulting hash:\n'
				+ result);
		authentication.verify(password1, result, function(err, result2) {
			if (result2) {
				console.log("\n\nConfirmed that hash \n" + result
						+ "\n verifies for password " + password1);
				rl.question('press enter to continue...', function (text) {
					hashSha256();
				});
				
			}
		});
	});
}

function hashSha256() {
	console.log('\nAt some point we upgrade to Sha256 with a 32 byte salt...')
	authentication.setAlgorithm('sha256');
	authentication.setLen(32);

	authentication.hash(password2, function(err, result) {
		sha256Hash = result;
		console.log('\nFor plaintext ' + password2 + ', resulting hash:\n'
				+ result);
		authentication.verify(password2, result, function(err, result2) {
			if (result2) {
				console.log("\n\nConfirmed that hash \n" + result
						+ "\n verifies for password " + password2);
				authentication.verify(password1, sha1Hash, function(err,
						result3, rehash) {
					if (result3) {
						console.log('And we can still verify the old hash, which our function re-hashes as ' + rehash + " so you can update the user credential");
						rl.question('press enter to continue...', function (text) {
							hashPKDF2800();
						});
					}
				});
			}
		});
	});
}

function hashPKDF2800() {
	console.log("\nNow we upgrade to PBKDF2 with 800 iterations...");
	authentication.setAlgorithm('pbkdf2');
	authentication.setIterations(800);
	authentication.setLen(64);
	authentication.hash(password3, function(err, result) {
		pbkdf2Hash = result;
		console.log('\nFor plaintext ' + password3
						+ ', resulting hash:\n' + result);
		authentication.verify(password3, result,
			function(err, result2) {
				if (result2) {
					console.log("\n\nConfirmed that hash \n"
									+ result
									+ "\n verifies for password "
									+ password3);
					authentication.verify(password1,sha1Hash,
						function(err, result3) {
							if (result3) {
								authentication.verify(password2, sha256Hash,
									function(err, result4) {
									console.log('And we can still verify the two older hashes!');
									rl.question('press enter to continue...', function (text) {
											hashPKDF210000();
									});
								});
							}
					});
				}
		});
	});
}

function hashPKDF210000() {
	console.log('\nNow we upgrade to PBKDF2 with 10000 iterations, 128 byte \
key/salt length...');
	authentication.setAlgorithm('pbkdf2');
	authentication.setIterations(10000);
	authentication.setLen(128);
	authentication.hash(password3, function(err, result) {
		pbkdf2Hash2 = result;
		console.log('\nFor plaintext ' + password3
						+ ', resulting hash:\n' + result);
		authentication.verify(password3, result, function(err, result2) {
			if (result2) {
				console.log("\n\nConfirmed that hash \n"
							 	+ result
								+ "\n verifies for password "
								+ password3);
				authentication.verify(password1, sha1Hash, 
						function(err, result3) {
					if (result3) {
						authentication.verify(password2, sha256Hash, 
								function(err, result4) {
							if (result4) {
								authentication.verify(password2, sha256Hash, 
										function(err,result4) {
									console.log('And we can still verify ' +
											'the three older hashes!');
									rl.question('press enter to continue...', function (text) {
										wrapSha1();
									});
								});
							}
						});
					}
				});
			}
		});
	});
}

function wrapSha1(){
	console.log('\nSo now if we still have the sha1 hash ' + sha1Hash
		+ ' around we can wrap it...');
	authentication.wrapSha1(sha1Hash, function(err, result) {
		console.log('For sha1 hash ' + sha1Hash + '\n the result is\n' + result);
		authentication.verify(password1, result, function(err, result2){
			console.log('And the original password ' + password1 + " verifies against this hash!");
			rl.close();
		});
	});
}