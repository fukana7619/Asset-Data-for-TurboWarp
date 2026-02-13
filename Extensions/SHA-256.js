(function(Scratch) {
  'use strict';

  async function sha256Hex(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map(b => ('0' + b.toString(16)).slice(-2))
      .join('');
    return hashHex;
  }

  class Sha256Extension {
    getInfo() {
      return {
        id: 'sha256ext',
        name: 'SHA-256',
        blocks: [
          {
            opcode: 'sha256',
            blockType: Scratch.BlockType.REPORTER,
            text: 'sha256 of [TEXT]',
            arguments: {
              TEXT: {
                type: Scratch.ArgumentType.STRING,
                defaultValue: 'hello'
              }
            }
          }
        ]
      };
    }

    sha256(args) {
      const text = args.TEXT + '';
      return sha256Hex(text);
    }
  }

  Scratch.extensions.register(new Sha256Extension());
})(Scratch);
