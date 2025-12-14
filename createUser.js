const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("database.db");

(async () => {
  const hash = await bcrypt.hash("wachtwoord123", 10);

  db.run(
    "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
    ["admin", hash],
    function(err) {
      if (err) {
        console.error("Fout bij aanmaken gebruiker:", err.message);
      } else {
        console.log("Admin gebruiker aangemaakt");
      }
      db.close();
    }
  );
})();
