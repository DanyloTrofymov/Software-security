const crypto = require('crypto');

// Клієнт ініціює рукостискання
function clientHello() {
  return crypto.randomBytes(16).toString('hex');
}


// Сервер відповідає своїм рукостисканням
// Сервер відповідає та генерує пару ключів
function serverHello() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { hello: crypto.randomBytes(16).toString('hex'), publicKey, privateKey };
}

const serverKeys = serverHello();

function sendPremasterSecret(serverPublicKey) {
  const premasterSecret = crypto.randomBytes(32);
  const encryptedPremaster = crypto.publicEncrypt(serverPublicKey, premasterSecret);
  return encryptedPremaster;
}

function generateSessionKeys(encryptedPremaster, privateKey) {
  const premasterSecret = crypto.privateDecrypt(privateKey, encryptedPremaster);
  // Тут можна використати premasterSecret для генерації сеансових ключів
  return { sessionKey: crypto.randomBytes(32) }; // Спрощена генерація ключа сеансу
}

function encryptWithSessionKey(sessionKey, message) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, iv);
  let encrypted = cipher.update(message);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { iv, encrypted };
}

function decryptWithSessionKey(sessionKey, encrypted, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

async function main() {
  console.log("Розпочинаємо TLS/SSL рукостискання");

  // Клієнт ініціює рукостискання
  const clientHelloMessage = clientHello();
  console.log("Клієнт привітання:", clientHelloMessage);

  // Сервер відповідає і генерує пару ключів
  const serverResponse = serverHello();
  console.log("Сервер привітання:", serverResponse.hello);

  // Клієнт надсилає зашифрований premaster secret
  const encryptedPremaster = sendPremasterSecret(serverResponse.publicKey);
  console.log("Зашифрований premaster secret від клієнта:", encryptedPremaster.toString('hex'));

  // Сервер розшифровує premaster і обидва генерують ключі сеансу
  const sessionKeys = generateSessionKeys(encryptedPremaster, serverResponse.privateKey);
  console.log("Сеансовий ключ:", sessionKeys.sessionKey.toString('hex'));

  // Обмін повідомленнями "готовий"
  const { encrypted: clientReady } = encryptWithSessionKey(sessionKeys.sessionKey, 'готовий');
  const { encrypted: serverReady } = encryptWithSessionKey(sessionKeys.sessionKey, 'готовий');
  console.log("Клієнт готовий:", clientReady.toString('hex'));
  console.log("Сервер готовий:", serverReady.toString('hex'));

  // Демонстрація зашифрованої комунікації
  const testMessage = "Тестове повідомлення";
  const { iv: encIv, encrypted: encryptedMessage } = encryptWithSessionKey(sessionKeys.sessionKey, testMessage);
  console.log("Зашифроване повідомлення:", encryptedMessage.toString('hex'));

  const decryptedMessage = decryptWithSessionKey(sessionKeys.sessionKey, encryptedMessage, encIv);
  console.log("Розшифроване повідомлення:", decryptedMessage);

  console.log("TLS/SSL рукостискання завершено");
}

main();