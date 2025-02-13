const serverPublicJWT = null;

document.querySelector("#clear").onclick = () => {
  localStorage.removeItem("uuid");
  indexedDB.deleteDatabase("db");
  document.querySelector("#clear").disabled = true;
  document.querySelector("#register").disabled = true;
  document.querySelector("#get").disabled = true;
  document.querySelector("#console").innerText = "Refresh to regenerate key pair";
  document.querySelector("#uuid").innerText = "(empty)";
};

document.querySelector("#console").innerText = "Generating Key Pair...";
const keyPair = await new Promise((resolve) => {
  const request = indexedDB.open("db");
  request.onsuccess = (event) => {
    const db = event.target.result;
    try {
      db.transaction("keys").objectStore("keys").get("keyPair").onsuccess = (event) => {
        if (event.target.result) resolve(event.target.result.value);
      };
    } catch (e) {}
  };
  request.onupgradeneeded = (event) => {
    const db = event.target.result;
    const objectStore = db.createObjectStore("keys", { keyPath: "key" });
    objectStore.transaction.oncomplete = async (event) => {
      console.log("Generating key pair...");
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
      );
      console.log("Generated key pair");
      const customerObjectStore = db.transaction("keys", "readwrite").objectStore("keys");
      customerObjectStore.add({
        key: "keyPair",
        value: keyPair,
      }).onsuccess = (e) => {
        resolve(keyPair);
      };
    };
  };
});
document.querySelector("#clear").disabled = false;
document.querySelector("#console").innerText = "Generated Key Pair";

if (localStorage.getItem("uuid")) {
  document.querySelector("#register").disabled = true;
  document.querySelector("#get").disabled = false;
  document.querySelector("#uuid").innerText = localStorage.getItem("uuid");
} else {
  document.querySelector("#register").disabled = false;
  document.querySelector("#get").disabled = true;
}
document.querySelector("#register").onclick = async () => {
  document.querySelector("#console").innerText = "Submitting public key...";
  const hello = await fetch("/hello", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(await crypto.subtle.exportKey("jwk", keyPair.publicKey)),
  });

  document.querySelector("#console").innerText = "Resolving server challenge...";
  const ack = await fetch("/ack", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", uuid: hello.headers.get("uuid") },
    body: await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      keyPair.privateKey,
      await hello.arrayBuffer(),
    ),
  });

  if (ack.status === 204) {
    localStorage.setItem("uuid", hello.headers.get("uuid"));
    document.querySelector("#uuid").innerText = localStorage.getItem("uuid");
    document.querySelector("#register").disabled = true;
    document.querySelector("#get").disabled = false;
    document.querySelector("#console").innerText = "registration success";
  }
};
document.querySelector("#get").onclick = async () => {
  document.querySelector("#console").innerText = "getting encrypted message...";
  const res = await fetch("/get", {
    method: "GET",
    headers: { uuid: localStorage.getItem("uuid") },
  });
  const resBuffer = await res.arrayBuffer();
  document.querySelector("#encrypted").innerText = await new TextDecoder().decode(resBuffer);
  const decryptedText = await new TextDecoder().decode(
    await crypto.subtle.decrypt({ name: "RSA-OAEP" }, keyPair.privateKey, resBuffer),
  );
  document.querySelector("#console").innerText = `Client decrypted message: ${decryptedText}`;
  document.querySelector("#message").value = decryptedText;
};
const serverPublicKey = await crypto.subtle.importKey(
  "jwk",
  serverPublicJWT,
  {
    name: "RSA-OAEP",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["encrypt"],
);

document.querySelector("#send").onclick = async () => {
  document.querySelector("#console").innerText = "sending encrypted message...";
  const encryptedMessage = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    serverPublicKey,
    new TextEncoder().encode(document.querySelector("#message").value),
  );
  document.querySelector("#encrypted").innerText = new TextDecoder().decode(encryptedMessage);
  const res = await fetch("/send", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", uuid: localStorage.getItem("uuid") },
    body: encryptedMessage,
  });
  document.querySelector("#console").innerText = `Server decrypted message: ${await res.text()}`;
};
