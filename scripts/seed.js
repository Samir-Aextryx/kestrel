#!/usr/bin/env node
// Creates the first administrator when the database is empty.
import { seedAdmin } from "../server/auth.js";

const seeded = seedAdmin();
if (!seeded) {
  console.log("database already contains users; nothing to seed");
} else {
  console.log(`email:    ${seeded.email}`);
  console.log(`password: ${seeded.password}`);
  console.log("store the password now; it is not printed again");
}
