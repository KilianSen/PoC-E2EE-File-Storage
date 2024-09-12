# PoC E2EE File Storage without host access
This is a rough and probably unsecure proof of concept for a file storage service (python), where the host cannot access the files, but the users can share files with each other.

## !!DO NOT USE THIS IN PRODUCTION!!
This is nowhere near production ready.
I am not a security expert and have hacked this together in a few hours very late at night.
If you want to use this, take this as a spark of inspiration and write a proper implementation, 
with proper documentation, testing, and code review.
I am sure there are many security vulnerabilities in this code, maybe even huge oversights in the fundamental concept.

If you implement this, maybe let me know, I would love to see a proper implementation of this concept. (And maybe it can help others too)

## How it works
- User Registration:  
A file encryption key is generated and stored encrypted with the user's password.
- File Upload:  
A file-specific encryption key is generated and stored encrypted with the user's file encryption key, both is done client-side.
The file is encrypted with the file-specific encryption key and stored on the server.
A URI containing the file-specific encryption key in plain text is returned to the user.
- File Sharing:  
The URI can be shared with other users, who can then download and decrypt the file using the file-specific encryption key.
The host cannot read the files since the URI is not stored on the server, and the file-specific encryption key is only stored encrypted with the user's file encryption key, which is encrypted with the user's password.
- File Recovery:  
Users can recover the URI by logging in and requesting the file-specific encryption key, which is decrypted with the user's password.
- File Download:
The URI is used to retrieve the encrypted file.
The file is decrypted client-side using the file-specific encryption key contained in the URI.