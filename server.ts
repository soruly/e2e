import crypto from "node:crypto";
import fs from "node:fs/promises";

import bodyParser from "body-parser";
import express from "express";
import rateLimit from "express-rate-limit";

process.loadEnvFile();
const { SERVER_ADDR = "0.0.0.0", SERVER_PORT = 3000 } = process.env;

if (
  !(await fs.stat("public.json").catch(() => null)) ||
  !(await fs.stat("private.json").catch(() => null))
) {
  const keyPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "jwk",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "jwk",
      cipher: "aes-256-cbc",
      passphrase: "top secret",
    },
  });
  await fs.writeFile("public.json", JSON.stringify(keyPair.publicKey));
  await fs.writeFile("private.json", JSON.stringify(keyPair.privateKey));
}

const serverPrivateKey = await crypto.webcrypto.subtle.importKey(
  "jwk",
  JSON.parse(await fs.readFile("private.json", "utf8")),
  {
    name: "RSA-OAEP",
    hash: "SHA-256",
  },
  true,
  ["decrypt"],
);

const app = express();

app.disable("x-powered-by");

app.set("trust proxy", ["loopback", "linklocal", "uniquelocal"]);

app.use(rateLimit());

app.use(
  bodyParser.raw({
    verify: (req, res, buf, encoding) => {
      if (buf && buf.length) req.rawBody = buf.toString(encoding || "utf8");
    },
  }),
);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

await fs.mkdir("jwk", { recursive: true });
for (const e of await fs.readdir("jwk")) {
  const uuid = e.replace(".json", "");
  app.locals[uuid] = {
    uuid,
    publicKey: await crypto.webcrypto.subtle.importKey(
      "jwk",
      JSON.parse(await fs.readFile(`jwk/${e}`, "utf8")).publicKey,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"],
    ),
  };
}

app.post("/hello", async (req, res) => {
  try {
    const publicKey = await crypto.webcrypto.subtle.importKey(
      "jwk",
      req.body,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"],
    );

    const uuid = crypto.webcrypto.randomUUID();
    const challenge = crypto.webcrypto.getRandomValues(new Uint8Array(32));
    req.app.locals[uuid] = { publicKey, challenge };
    const encryptedChallenge = await crypto.webcrypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      challenge,
    );
    return res.header({ uuid }).type("octet-stream").end(Buffer.from(encryptedChallenge));
  } catch (e) {
    console.error(e);
    return res.sendStatus(400);
  }
});

app.post("/ack", async (req, res) => {
  if (!req.headers.uuid.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
    return res.sendStatus(400);
  }
  if (
    Buffer.from(new Uint8Array(req.app.locals[req.headers.uuid].challenge)).toString("hex") ===
    Buffer.from(new Uint8Array(req.body)).toString("hex")
  ) {
    await fs.writeFile(
      `jwk/${req.headers.uuid}.json`,
      JSON.stringify(
        {
          created: new Date().toISOString(),
          uuid: req.headers.uuid,
          ip: req.ip,
          agent: req.headers["user-agent"],
          publicKey: await crypto.webcrypto.subtle.exportKey(
            "jwk",
            req.app.locals[req.headers.uuid].publicKey,
          ),
        },
        null,
        2,
      ),
    );
    return res.sendStatus(204);
  }
  return res.status(403);
});

app.get("/get", async (req, res) => {
  if (!req.headers.uuid.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
    return res.sendStatus(400);
  }
  await fs.utimes(`jwk/${req.headers.uuid}.json`, new Date(), new Date());
  return res
    .type("octet-stream")
    .end(
      Buffer.from(
        await crypto.webcrypto.subtle.encrypt(
          { name: "RSA-OAEP" },
          req.app.locals[req.headers.uuid].publicKey,
          Buffer.from(
            `pid: ${process.pid}, platform ${process.arch} ${
              process.platform
            } server time now is ${new Date().toISOString()}`,
          ),
        ),
      ),
    );
});

app.post("/send", async (req, res) => {
  const decodedMessage = await new TextDecoder().decode(
    Buffer.from(
      await crypto.webcrypto.subtle.decrypt({ name: "RSA-OAEP" }, serverPrivateKey, req.body),
    ),
  );
  console.log(`Received message: ${decodedMessage}`);
  return res.send(decodedMessage);
});

app.get("/index.js", async (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  return res.send(
    (await fs.readFile("index.js", "utf8")).replace(
      "const serverPublicJWT = null;",
      `const serverPublicJWT = ${await fs.readFile("public.json", "utf8")}`,
    ),
  );
});

app.get("/", async (req, res) => {
  res.setHeader("Content-Type", "text/html");
  return res.send(await fs.readFile("index.html", "utf8"));
});

app.listen(SERVER_PORT, SERVER_ADDR, () =>
  console.log(`Server listening on ${SERVER_ADDR}:${SERVER_PORT}`),
);
