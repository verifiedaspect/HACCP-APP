const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const db = new sqlite3.Database("database.db");

// ==========================
// MIDDLEWARE
// ==========================
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({ secret: "haccp-secret", resave: false, saveUninitialized: false }));

// ==========================
// HELPER FUNCTIES
// ==========================
function formatDatumNederlands() {
  return new Intl.DateTimeFormat('nl-NL', {
    timeZone: 'Europe/Amsterdam',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).format(new Date());
}

// ==========================
// DATABASE TABELLEN
// ==========================
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS checklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    taak TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS checklist_rapport (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datumtijd TEXT,
    score REAL,
    data TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS koeltemperaturen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datumtijd TEXT,
    invuller TEXT,
    kaas REAL,
    vlees REAL,
    grijs REAL,
    worsten REAL,
    zuivel REAL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS grilworsten (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datumtijd TEXT,
    invuller TEXT,
    varken_naturel REAL,
    varken_kaas REAL,
    kip REAL,
    piri_piri REAL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS overige_temperaturen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datumtijd TEXT,
    invuller TEXT,
    product TEXT,
    temperatuur REAL
  )`);

  // Vul checklist als leeg
  const taken = [
    "Resterende boter in folie en gekoeld",
    "Resterende noten afgedekt/ingepakt",
    "Weegschaal schoongemaakt",
    "Werkbank boterhoek schoongemaakt",
    "Werkbank naast oven schoongemaakt",
    "Oven schoongemaakt (reiningsprogramma)",
    "Snijmachine (+ werkbank snijmachine) schoongemaakt",
    "Grilworsten gevacumeerd en gekoeld",
    "Genderse borrelmix gevacumeerd en gekoeld (indien op zaterdag verdelen over personeel)",
    "Grilworsten bakken (afgewassen) en opgeborgen",
    "Snijplank + mes grilworsten afgewassen",
    "'Vitrine' grilworsten schoongemaakt (inclusief bordjes)",
    "Snijplanken in het bad (kaasmakerij) ~ boterplanken + kaasplanken + witte planken",
    "Kaasmessen afgewassen + opgehangen",
    "Kaasschaven afgewassen + opgeborgen",
    "Werkbank kassa schoongemaakt ~ gebied waar de kaasplanken liggen",
    "Kassa schoongemaakt ~ weegschaal, scherm medewerker, scherm klant",
    "Kazen gekoeld (indien van toepassing)",
    "Kleine stukken kaas gevacummeerd en gekoeld",
    "Verlichting uitgeschakeld koelingen ~ Kaas, vlees- en zuivelkoeling",
    "Proefbakjes geleegd (afgewassen) en opgeborgen",
    "Toonbank schoongemaakt",
    "Pin apparaten schoongemaakt",
    "Afwas afgewerkt",
    "Vieze doeken in de wasmand(en)",
    "Schone doeken in de kast",
    "Stofzuigen",
    "Dwijlen (indien van toepassing)",
    "Prullenbakken geleegd (+ nieuwe zak erin)",
    "Buiten afgesloten ~ vlaggen binnenhalen, bord op gesloten en deur op slot"
  ];

  db.get("SELECT COUNT(*) as cnt FROM checklist", [], (err, row) => {
    if (row && row.cnt === 0) {
      const stmt = db.prepare("INSERT INTO checklist (taak) VALUES (?)");
      taken.forEach(t => stmt.run(t));
      stmt.finalize();
    }
  });
});

// ==========================
// ADMIN GEBRUIKER
// ==========================
const adminUsername = "admin";
const adminPassword = "admin"; // verander dit na eerste login
db.get("SELECT * FROM users WHERE username = ?", [adminUsername], async (err, row) => {
  if (!row) {
    const hash = await bcrypt.hash(adminPassword, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [adminUsername, hash]);
    console.log("Admin gebruiker aangemaakt: username=admin, wachtwoord=admin");
  }
});

// ==========================
// LOGIN ROUTES
// ==========================
function renderLogin(foutmelding = "") {
  return `
<!DOCTYPE html>
<html lang="nl">
<head><meta charset="UTF-8"><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 font-sans flex items-center justify-center h-screen">
<div class="bg-white p-8 rounded-xl shadow-md w-full max-w-md">
<h2 class="text-2xl font-bold mb-6 text-center">HACCP Login</h2>
${foutmelding ? `<p class="text-red-600 mb-4 text-center font-semibold">${foutmelding}</p>` : ""}
<form method="POST" action="/login" class="space-y-4">
<input name="username" placeholder="Gebruikersnaam" required class="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400">
<input name="password" type="password" placeholder="Wachtwoord" required class="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400">
<button type="submit" class="w-full bg-blue-500 text-white py-2 rounded hover:bg-blue-600 transition">Inloggen</button>
</form>
</div></body></html>`;
}

app.get("/", (req, res) => res.send(renderLogin()));

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    let fout = "";
    if (err) fout = "Database fout";
    else if (!user) fout = "Gebruiker niet gevonden";
    else if (!(await bcrypt.compare(password, user.password))) fout = "Onjuist wachtwoord";
    else { req.session.userId = user.id; return res.redirect("/dashboard"); }
    res.send(renderLogin(fout));
  });
});

// ==========================
// DASHBOARD
// ==========================
app.get("/dashboard", (req, res) => {
  if (!req.session.userId) return res.redirect("/");

  res.send(`
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<script src="https://cdn.tailwindcss.com"></script>
<title>HACCP Dashboard</title>
</head>
<body class="bg-gray-100 font-sans min-h-screen">

<header class="bg-yellow-500 text-white p-4 flex items-center justify-between shadow-md">
  <h1 class="text-lg font-bold mx-auto">HACCP Systeem - Kaasboerderij De Lange Hoeve</h1>
</header>

<main class="max-w-4xl mx-auto space-y-8 p-6">

  <div class="bg-white p-6 rounded-xl shadow-md">
    <h2 class="text-xl font-bold mb-4">HACCP Controle</h2>
    <div class="space-y-2">
      <a href="/checklist/new" class="block px-4 py-2 bg-yellow-400 text-white rounded hover:bg-yellow-500 transition">Nieuwe Checklist</a>
      <a href="/checklist/list" class="block px-4 py-2 bg-yellow-300 text-white rounded hover:bg-yellow-400 transition">Checklist Rapporten</a>
    </div>
  </div>

  <div class="bg-white p-6 rounded-xl shadow-md">
    <h2 class="text-xl font-bold mb-4">Temperatuur Metingen</h2>
    <div class="space-y-2">
      <a href="/temperaturen" class="block px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 transition">Temperatuur Koelingen</a>
      <a href="/grilworsten" class="block px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 transition">Temperaturen Grilworsten</a>
      <a href="/temperaturen-overige" class="block px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 transition">Temperaturen Overige</a>
    </div>
  </div>

  <div class="bg-white p-6 rounded-xl shadow-md">
    <h2 class="text-xl font-bold mb-4">Sessie</h2>
    <div class="space-y-2">
      <a href="/logout" class="block px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 transition">Uitloggen</a>
    </div>
  </div>

</main>
</body>
</html>
  `);
});

app.get("/logout", (req, res) => { req.session.destroy(); res.redirect("/"); });

// ==========================
// LOGS VERWIJDEREN ROUTES
// ==========================
app.post("/temperaturen/delete/:id", (req, res) => {
  db.run("DELETE FROM koeltemperaturen WHERE id = ?", [req.params.id], err => res.redirect("/temperaturen"));
});

app.post("/grilworsten/delete/:id", (req, res) => {
  db.run("DELETE FROM grilworsten WHERE id = ?", [req.params.id], err => res.redirect("/grilworsten"));
});

app.post("/temperaturen-overige/delete/:id", (req, res) => {
  db.run("DELETE FROM overige_temperaturen WHERE id = ?", [req.params.id], err => res.redirect("/temperaturen-overige"));
});

app.post("/checklist/delete/:id", (req, res) => {
  db.run("DELETE FROM checklist_rapport WHERE id = ?", [req.params.id], err => res.redirect("/checklist/list"));
});

// ==========================
// TEMPERATUREN KOELINGEN
// ==========================
app.get("/temperaturen", (req, res) => {
  if (!req.session.userId) return res.redirect("/");
  db.all("SELECT * FROM koeltemperaturen ORDER BY datumtijd DESC", [], (err, logs) => {
    if (err) return res.send("Fout bij ophalen logboek");

    let html = `
<!DOCTYPE html><html lang="nl"><head><meta charset="UTF-8"><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-6">
<div class="max-w-5xl mx-auto bg-white p-8 rounded-xl shadow-md">
<h2 class="text-2xl font-bold mb-6 text-center">Temperaturen Koelingen</h2>

<!-- Nieuwe Waarneming Form -->
<form method="POST" action="/temperaturen" class="space-y-4">
<div><label class="block font-medium mb-2">Invuller</label>
<input name="invuller" placeholder="Naam invuller" required class="w-full md:w-1/2 px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400"></div>
<div class="grid grid-cols-1 md:grid-cols-5 gap-4 mt-4">
<div><label class="block mb-1">Kaas koeling</label><input name="kaas" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Vlees koeling</label><input name="vlees" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Grijze koeling</label><input name="grijs" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Worsten koeling</label><input name="worsten" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Zuivelkoeling</label><input name="zuivel" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
</div>
<button class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600 mt-4">Opslaan Waarneming</button>
</form>

<h3 class="text-xl font-bold mt-8 mb-4">Logboek</h3>
<div class="space-y-4">`;

    logs.forEach(log => {
      html += `
<div class="bg-gray-100 p-4 rounded shadow-sm flex justify-between items-start">
<div>
<p><strong>Datum/Tijd:</strong> ${log.datumtijd}</p>
<p><strong>Invuller:</strong> ${log.invuller}</p>
<div class="grid grid-cols-1 md:grid-cols-5 gap-4 mt-2">
  <div>Kaas: ${log.kaas}°C</div>
  <div>Vlees: ${log.vlees}°C</div>
  <div>Grijs: ${log.grijs}°C</div>
  <div>Worsten: ${log.worsten}°C</div>
  <div>Zuivel: ${log.zuivel}°C</div>
</div>
</div>
<form method="POST" action="/temperaturen/delete/${log.id}">
<button class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600">Verwijderen</button>
</form>
</div>`;
    });

    html += `</div></div></body></html>`;
    res.send(html);
  });
});

app.post("/temperaturen", (req, res) => {
  const { invuller, kaas, vlees, grijs, worsten, zuivel } = req.body;
  const datumtijd = formatDatumNederlands();
  db.run("INSERT INTO koeltemperaturen (datumtijd, invuller, kaas, vlees, grijs, worsten, zuivel) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [datumtijd, invuller, kaas, vlees, grijs, worsten, zuivel],
    err => res.redirect("/temperaturen")
  );
});

// ==========================
// TEMPERATUREN GRILWORSTEN
// ==========================
app.get("/grilworsten", (req, res) => {
  if (!req.session.userId) return res.redirect("/");
  db.all("SELECT * FROM grilworsten ORDER BY datumtijd DESC", [], (err, logs) => {
    if (err) return res.send("Fout bij ophalen logboek");

    let html = `
<!DOCTYPE html><html lang="nl"><head><meta charset="UTF-8"><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-6"><div class="max-w-5xl mx-auto bg-white p-8 rounded-xl shadow-md">
<h2 class="text-2xl font-bold mb-6 text-center">Temperaturen Grilworsten</h2>
<form method="POST" action="/grilworsten" class="space-y-4">
<div><label class="block font-medium mb-2">Invuller</label>
<input name="invuller" placeholder="Naam invuller" required class="w-full md:w-1/2 px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400"></div>
<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
<div><label class="block mb-1">Varken naturel</label><input name="varken_naturel" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Varken Kaas</label><input name="varken_kaas" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Kip</label><input name="kip" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
<div><label class="block mb-1">Piri piri</label><input name="piri_piri" type="number" step="0.1" required class="w-full border p-2 rounded"></div>
</div>
<button class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600 mt-4">Opslaan Waarneming</button>
</form>

<h3 class="text-xl font-bold mt-8 mb-4">Logboek</h3>
<div class="space-y-4">`;

    logs.forEach(log => {
      html += `
<div class="bg-gray-100 p-4 rounded shadow-sm flex justify-between items-start">
<div>
<p><strong>Datum/Tijd:</strong> ${log.datumtijd}</p>
<p><strong>Invuller:</strong> ${log.invuller}</p>
<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mt-2">
  <div>Varken naturel: ${log.varken_naturel}°C</div>
  <div>Varken Kaas: ${log.varken_kaas}°C</div>
  <div>Kip: ${log.kip}°C</div>
  <div>Piri piri: ${log.piri_piri}°C</div>
</div>
</div>
<form method="POST" action="/grilworsten/delete/${log.id}">
<button class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600">Verwijderen</button>
</form>
</div>`;
    });

    html += `</div></div></body></html>`;
    res.send(html);
  });
});

app.post("/grilworsten", (req, res) => {
  const { invuller, varken_naturel, varken_kaas, kip, piri_piri } = req.body;
  const datumtijd = formatDatumNederlands();
  db.run("INSERT INTO grilworsten (datumtijd, invuller, varken_naturel, varken_kaas, kip, piri_piri) VALUES (?, ?, ?, ?, ?, ?)",
    [datumtijd, invuller, varken_naturel, varken_kaas, kip, piri_piri],
    err => res.redirect("/grilworsten")
  );
});

// ==========================
// TEMPERATUREN OVERIGE
// ==========================
app.get("/temperaturen-overige", (req, res) => {
  if (!req.session.userId) return res.redirect("/");

  db.all("SELECT * FROM overige_temperaturen ORDER BY datumtijd DESC", [], (err, logs) => {
    if (err) return res.send("Fout bij ophalen logboek");

    let html = `
<!DOCTYPE html><html lang="nl"><head><meta charset="UTF-8"><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-6"><div class="max-w-5xl mx-auto bg-white p-8 rounded-xl shadow-md">
<h2 class="text-2xl font-bold mb-6 text-center">Temperaturen Overige</h2>
<form method="POST" action="/temperaturen-overige" class="space-y-4">
<div><label class="block font-medium mb-2">Invuller</label>
<input name="invuller" placeholder="Naam invuller" required class="w-full md:w-1/2 px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400"></div>
<div><label class="block font-medium mb-2">Productnaam</label>
<input name="product" placeholder="Naam product" required class="w-full md:w-1/2 px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400"></div>
<div><label class="block font-medium mb-2">Temperatuur (°C)</label>
<input name="temperatuur" type="number" step="0.1" required class="w-full md:w-1/3 px-4 py-2 border rounded"></div>
<button class="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600 mt-4">Opslaan Waarneming</button>
</form>

<h3 class="text-xl font-bold mt-8 mb-4">Logboek</h3>
<div class="space-y-4">`;

    logs.forEach(log => {
      html += `
<div class="bg-gray-100 p-4 rounded shadow-sm flex justify-between items-start">
<div>
<p><strong>Datum/Tijd:</strong> ${log.datumtijd}</p>
<p><strong>Invuller:</strong> ${log.invuller}</p>
<p><strong>Product:</strong> ${log.product}</p>
<p><strong>Temperatuur:</strong> ${log.temperatuur}°C</p>
</div>
<form method="POST" action="/temperaturen-overige/delete/${log.id}">
<button class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600">Verwijderen</button>
</form>
</div>`;
    });

    html += `</div></div></body></html>`;
    res.send(html);
  });
});

app.post("/temperaturen-overige", (req, res) => {
  const { invuller, product, temperatuur } = req.body;
  const datumtijd = formatDatumNederlands();
  db.run("INSERT INTO overige_temperaturen (datumtijd, invuller, product, temperatuur) VALUES (?, ?, ?, ?)",
    [datumtijd, invuller, product, temperatuur],
    err => res.redirect("/temperaturen-overige")
  );
});

// ==========================
// CHECKLIST LIST MET VERWIJDEREN
// ==========================
app.get("/checklist/list", (req, res) => {
  if (!req.session.userId) return res.redirect("/");

  db.all("SELECT * FROM checklist_rapport ORDER BY datumtijd DESC", [], (err, rows) => {
    if (err) return res.send("Fout bij ophalen rapporten");

    let html = `<!DOCTYPE html>
<html lang="nl"><head><meta charset="UTF-8"><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-6"><div class="max-w-4xl mx-auto bg-white p-6 rounded-xl shadow-md">
<h1 class="text-xl font-bold mb-4">Checklijst Rapporten</h1>
<a href="/dashboard" class="text-blue-500 mb-4 inline-block">Dashboard</a>
<a href="/checklist/new" class="text-blue-500 mb-4 inline-block ml-4">Nieuwe Checklist</a>
<table class="min-w-full bg-white shadow-md rounded overflow-hidden mt-4">
<thead class="bg-gray-200 text-gray-700">
<tr><th class="py-2 px-4">Datum/Tijd</th><th class="py-2 px-4">Eindscore</th><th class="py-2 px-4">Bekijk</th><th class="py-2 px-4">Verwijderen</th></tr>
</thead>
<tbody class="text-gray-800">`;

    rows.forEach(r => {
      html += `<tr class="border-b hover:bg-gray-100">
<td class="py-2 px-4">${r.datumtijd}</td>
<td class="py-2 px-4">${r.score}</td>
<td class="py-2 px-4"><a href="/checklist/view/${r.id}" class="text-blue-500">Bekijk</a></td>
<td class="py-2 px-4">
<form method="POST" action="/checklist/delete/${r.id}">
<button class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600">Verwijderen</button>
</form>
</td>
</tr>`;
    });

    html += `</tbody></table></div></body></html>`;
    res.send(html);
  });
});

// ==========================
// SERVER START
// ==========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`HACCP webapp draait op http://localhost:${PORT}`));

