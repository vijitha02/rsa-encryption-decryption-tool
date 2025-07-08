// RSA Implementation
class RSA {
    constructor() {
        this.publicKey = null;
        this.privateKey = null;
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
        this.chunkSize = 50; // Maximum characters per chunk
    }

    isPrime(n, k = 5) {
        if (n <= 1n) return false;
        if (n <= 3n) return true;
        if (n % 2n === 0n) return false;

        let d = n - 1n;
        let s = 0n;
        while (d % 2n === 0n) {
            d /= 2n;
            s++;
        }

        for (let i = 0; i < k; i++) {
            const a = 2n + BigInt(Math.floor(Math.random() * Number(n - 3n)));
            let x = this.modularExponentiation(a, d, n);
            if (x === 1n || x === n - 1n) continue;

            let j;
            for (j = 0n; j < s - 1n; j++) {
                x = this.modularExponentiation(x, 2n, n);
                if (x === n - 1n) break;
            }
            if (j === s - 1n) return false;
        }
        return true;
    }

    generatePrime(bits) {
        while (true) {
            const p = this.randomBigInt(bits);
            if (this.isPrime(p)) return p;
        }
    }

    randomBigInt(bits) {
        let result = 1n;
        for (let i = 0; i < bits - 1; i++) {
            result = (result << 1n) | BigInt(Math.random() > 0.5);
        }
        return result | 1n;
    }

    extendedGcd(a, b) {
        if (a === 0n) return [b, 0n, 1n];
        const [g, x, y] = this.extendedGcd(b % a, a);
        return [g, y - (b / a) * x, x];
    }

    modinv(a, m) {
        const [g, x] = this.extendedGcd(a, m);
        if (g !== 1n) throw new Error('Modular inverse does not exist');
        return (x % m + m) % m;
    }

    modularExponentiation(base, exponent, modulus) {
        let result = 1n;
        base = base % modulus;
        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exponent = exponent / 2n;
            base = (base * base) % modulus;
        }
        return result;
    }

    generateKeys(bits = 1024) {
        const p = this.generatePrime(bits / 2);
        const q = this.generatePrime(bits / 2);
        const n = p * q;
        const phi = (p - 1n) * (q - 1n);
        let e = 65537n;

        while (this.extendedGcd(e, phi)[0] !== 1n) {
            e = this.randomBigInt(16);
        }

        const d = this.modinv(e, phi);
        this.publicKey = [e, n];
        this.privateKey = [d, n];
        return [this.publicKey, this.privateKey];
    }

    stringToBigInt(str) {
        const bytes = this.encoder.encode(str);
        let result = 0n;
        for (let i = 0; i < bytes.length; i++) {
            result = (result << 8n) | BigInt(bytes[i]);
        }
        return result;
    }

    bigIntToString(num) {
        const bytes = [];
        while (num > 0n) {
            bytes.unshift(Number(num & 0xffn));
            num = num >> 8n;
        }
        if (bytes.length === 0) return '';
        try {
            return this.decoder.decode(new Uint8Array(bytes));
        } catch (e) {
            console.error('Decoding error:', e);
            return 'Decryption error: Invalid message format';
        }
    }

    encrypt(message) {
        if (!this.publicKey) throw new Error('Public key not generated');
        const [e, n] = this.publicKey;
        
        // Split message into chunks
        const chunks = [];
        for (let i = 0; i < message.length; i += this.chunkSize) {
            chunks.push(message.slice(i, i + this.chunkSize));
        }
        
        // Encrypt each chunk
        const encryptedChunks = chunks.map(chunk => {
            const messageInt = this.stringToBigInt(chunk);
            if (messageInt >= n) {
                throw new Error('Message too long for current key size');
            }
            return this.modularExponentiation(messageInt, e, n).toString();
        });
        
        return encryptedChunks.join('|'); // Use | as separator
    }

    decrypt(ciphertext) {
        if (!this.privateKey) throw new Error('Private key not generated');
        const [d, n] = this.privateKey;
        
        // Split ciphertext into chunks
        const encryptedChunks = ciphertext.split('|');
        
        // Decrypt each chunk
        const decryptedChunks = encryptedChunks.map(chunk => {
            const decrypted = this.modularExponentiation(BigInt(chunk), d, n);
            return this.bigIntToString(decrypted);
        });
        
        return decryptedChunks.join('');
    }

    async encryptFile(file) {
        if (!this.publicKey) throw new Error('Public key not generated');
        const [e, n] = this.publicKey;
        
        // Read file as text
        const text = await file.text();
        
        // Split text into chunks and encrypt each chunk
        const chunks = [];
        for (let i = 0; i < text.length; i += this.chunkSize) {
            const chunk = text.slice(i, i + this.chunkSize);
            const messageInt = this.stringToBigInt(chunk);
            if (messageInt >= n) {
                throw new Error('Message too long for current key size');
            }
            const encrypted = this.modularExponentiation(messageInt, e, n);
            chunks.push(encrypted.toString());
        }
        
        // Join encrypted chunks with separator
        const encryptedText = chunks.join('|');
        
        // Create blob with encrypted text
        return new Blob([encryptedText], { type: 'text/plain' });
    }

    async decryptFile(file) {
        if (!this.privateKey) throw new Error('Private key not generated');
        const [d, n] = this.privateKey;
        
        // Read file as text
        const encryptedText = await file.text();
        
        // Split into chunks and decrypt each chunk
        const encryptedChunks = encryptedText.split('|');
        const decryptedChunks = encryptedChunks.map(chunk => {
            const decrypted = this.modularExponentiation(BigInt(chunk), d, n);
            return this.bigIntToString(decrypted);
        });
        
        // Join decrypted chunks
        const decryptedText = decryptedChunks.join('');
        
        // Create blob with decrypted text
        return new Blob([decryptedText], { type: 'text/plain' });
    }
}

// UI Interaction
document.addEventListener('DOMContentLoaded', () => {
    const rsa = new RSA();
    const generateKeysBtn = document.getElementById('generateKeys');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const encryptFileBtn = document.getElementById('encryptFileBtn');
    const decryptFileBtn = document.getElementById('decryptFileBtn');
    const fileToEncrypt = document.getElementById('fileToEncrypt');
    const fileToDecrypt = document.getElementById('fileToDecrypt');
    const publicKeyDisplay = document.getElementById('publicKey');
    const privateKeyDisplay = document.getElementById('privateKey');
    const messageInput = document.getElementById('message');
    const ciphertextInput = document.getElementById('ciphertext');
    const encryptedResult = document.getElementById('encryptedResult');
    const decryptedResult = document.getElementById('decryptedResult');
    const encryptedFileStatus = document.getElementById('encryptedFileStatus');
    const decryptedFileStatus = document.getElementById('decryptedFileStatus');
    const downloadEncrypted = document.getElementById('downloadEncrypted');
    const downloadDecrypted = document.getElementById('downloadDecrypted');

    generateKeysBtn.addEventListener('click', () => {
        try {
            const [publicKey, privateKey] = rsa.generateKeys(256); // Increased key size to 256 bits
            publicKeyDisplay.textContent = `(${publicKey[0]}, ${publicKey[1]})`;
            privateKeyDisplay.textContent = `(${privateKey[0]}, ${privateKey[1]})`;
            messageInput.value = '';
            ciphertextInput.value = '';
            encryptedResult.textContent = 'No encrypted message yet';
            decryptedResult.textContent = 'No decrypted message yet';
        } catch (error) {
            alert('Error generating keys: ' + error.message);
        }
    });

    encryptBtn.addEventListener('click', () => {
        try {
            const message = messageInput.value;
            if (!message) {
                alert('Please enter a message to encrypt');
                return;
            }
            const ciphertext = rsa.encrypt(message);
            encryptedResult.textContent = ciphertext;
            ciphertextInput.value = ciphertext;
        } catch (error) {
            alert('Error during encryption: ' + error.message);
        }
    });

    decryptBtn.addEventListener('click', () => {
        try {
            const ciphertext = ciphertextInput.value;
            if (!ciphertext) {
                alert('Please enter ciphertext to decrypt');
                return;
            }
            const decrypted = rsa.decrypt(ciphertext);
            decryptedResult.textContent = decrypted;
        } catch (error) {
            alert('Error during decryption: ' + error.message);
        }
    });

    encryptFileBtn.addEventListener('click', async () => {
        try {
            const file = fileToEncrypt.files[0];
            if (!file) {
                alert('Please select a file to encrypt');
                return;
            }
            
            encryptedFileStatus.textContent = 'Encrypting...';
            const encryptedBlob = await rsa.encryptFile(file);
            
            // Create download link
            const url = URL.createObjectURL(encryptedBlob);
            downloadEncrypted.href = url;
            downloadEncrypted.download = 'encrypted_' + file.name;
            downloadEncrypted.style.display = 'inline-block';
            
            encryptedFileStatus.textContent = `File encrypted successfully: ${file.name}`;
        } catch (error) {
            encryptedFileStatus.textContent = 'Error: ' + error.message;
            downloadEncrypted.style.display = 'none';
        }
    });

    decryptFileBtn.addEventListener('click', async () => {
        try {
            const file = fileToDecrypt.files[0];
            if (!file) {
                alert('Please select a file to decrypt');
                return;
            }
            
            decryptedFileStatus.textContent = 'Decrypting...';
            const decryptedBlob = await rsa.decryptFile(file);
            
            // Create download link
            const url = URL.createObjectURL(decryptedBlob);
            downloadDecrypted.href = url;
            downloadDecrypted.download = 'decrypted_' + file.name;
            downloadDecrypted.style.display = 'inline-block';
            
            decryptedFileStatus.textContent = `File decrypted successfully: ${file.name}`;
        } catch (error) {
            decryptedFileStatus.textContent = 'Error: ' + error.message;
            downloadDecrypted.style.display = 'none';
        }
    });
}); 