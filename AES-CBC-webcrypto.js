(function (Scratch) {
  'use strict';

  // Web Crypto API が使えるかチェック
  const hasWebCrypto =
    typeof crypto !== 'undefined' &&
    crypto.subtle &&
    typeof TextEncoder !== 'undefined' &&
    typeof TextDecoder !== 'undefined';

  // UTF-8 エンコード／デコード
  const encoder = hasWebCrypto ? new TextEncoder() : null;
  const decoder = hasWebCrypto ? new TextDecoder() : null;

  // ArrayBuffer → Base64
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Base64 → Uint8Array
  function base64ToUint8Array(base64) {
    try {
      const binary = atob(base64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (e) {
      return null;
    }
  }

  // パスワード文字列 → AES鍵（SHA-256で32バイト鍵にする）
  async function deriveKeyFromPassword(password) {
    const pwBytes = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', pwBytes);
    return crypto.subtle.importKey(
      'raw',
      hash,
      { name: 'AES-CBC' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  class AESCryptoExtension {
    getInfo() {
      return {
        id: 'aesCrypto',
        name: 'AES暗号化',
        blocks: [
          {
            opcode: 'encrypt',
            blockType: Scratch.BlockType.REPORTER,
            text: '暗号化 キー [KEY] 内容 [TEXT]',
            arguments: {
              KEY: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'password123'
              },
              TEXT: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'Hello World'
              }
            }
          },
          {
            opcode: 'decrypt',
            blockType: Scratch.BlockType.REPORTER,
            text: '復号化 キー [KEY] 内容 [CIPHER]',
            arguments: {
              KEY: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'password123'
              },
              CIPHER: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: '暗号文'
              }
            }
          }
        ]
      };
    }

    // 暗号化（AES-CBC, IV付き, Base64で返す）
    async encrypt(args) {
      if (!hasWebCrypto) {
        return 'Error: WebCrypto not available';
      }

      const keyStr = String(args.KEY);
      const textStr = String(args.TEXT);

      try {
        const key = await deriveKeyFromPassword(keyStr);

        // ランダムIV（16バイト）
        const iv = crypto.getRandomValues(new Uint8Array(16));

        // 平文をUTF-8バイト列に
        const plaintext = encoder.encode(textStr);

        // AES-CBCで暗号化
        const cipherBuffer = await crypto.subtle.encrypt(
          { name: 'AES-CBC', iv },
          key,
          plaintext
        );

        // 先頭にIVをくっつけて保存形式にする
        const ivAndCipher = new Uint8Array(iv.byteLength + cipherBuffer.byteLength);
        ivAndCipher.set(iv, 0);
        ivAndCipher.set(new Uint8Array(cipherBuffer), iv.byteLength);

        // Base64文字列にして返す
        return arrayBufferToBase64(ivAndCipher.buffer);
      } catch (e) {
        console.error(e);
        return 'Error: encrypt failed';
      }
    }

    // 復号化（Base64 → IV + Cipher → AES-CBC）
    async decrypt(args) {
      if (!hasWebCrypto) {
        return 'Error: WebCrypto not available';
      }

      const keyStr = String(args.KEY);
      const cipherBase64 = String(args.CIPHER);

      try {
        const ivAndCipher = base64ToUint8Array(cipherBase64);
        if (!ivAndCipher || ivAndCipher.byteLength <= 16) {
          return 'Error: invalid cipher';
        }

        // 先頭16バイトがIV
        const iv = ivAndCipher.slice(0, 16);
        const cipherBytes = ivAndCipher.slice(16);

        const key = await deriveKeyFromPassword(keyStr);

        const plainBuffer = await crypto.subtle.decrypt(
          { name: 'AES-CBC', iv },
          key,
          cipherBytes
        );

        const text = decoder.decode(plainBuffer);
        return text;
      } catch (e) {
        console.error(e);
        return 'Error: wrong key or invalid data';
      }
    }
  }

  Scratch.extensions.register(new AESCryptoExtension());
})(Scratch);