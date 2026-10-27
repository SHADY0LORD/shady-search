#!/usr/bin/env node
import { randomBytes, pbkdf2Sync } from "node:crypto";
import { stdin } from "node:process";

const chunks = [];
stdin.setEncoding("utf8");
for await (const chunk of stdin) chunks.push(chunk);
const password = chunks.join("").replace(/[\r\n]+$/, "");
if (password.length < 12) {
  console.error("Use a password with at least 12 characters.");
  process.exit(1);
}
const iterations = 210000;
const salt = randomBytes(16);
const hash = pbkdf2Sync(password, salt, iterations, 32, "sha256");
const b64url = (buffer) => buffer.toString("base64url");
console.log(`pbkdf2-sha256$${iterations}$${b64url(salt)}$${b64url(hash)}`);
