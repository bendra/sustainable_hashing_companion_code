sustainable_hashing_companion_code
==================================

Companion code for my <a href="https://medium.com/@uther_bendragon/sustainable-password-hashing-8c6bd5de3844">Sustainable Password Hashing article</a>.  The code in src/authentication.js and requires a node.js runtime environment.  
The module can 
* Hash passwords using a "preferred" algorithm/hash length/iteration count
* Verify passwords against credentials hashed with the sha1, sha256, and pkbdf2 algorithms 
* Wrap sha1 hashed credentials with pbkdf2 as described in the Sustainable Password Hashing article, and verify against the resulting hash.
* Easily be extended to add new algorithms. 
* In development mode you can change the preferred algorithm/hash length/iteration count to test and explore various scenarios

The script src/authentication_runner.js does a "walkthrough" of most of these features.

This code is primarily intended to be didactic but you are welcome to use it for any reason you would like; see LICENSE.md 
