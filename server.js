const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SECRET_123";

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role VARCHAR(30) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      type VARCHAR(20) NOT NULL,
      category VARCHAR(150),
      description TEXT,
      amount NUMERIC(14,2) NOT NULL,
      date DATE NOT NULL,
      created_by VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const result = await pool.query(
    "SELECT id FROM users WHERE username='admin'"
  );

  if (result.rows.length === 0) {
    const hash = await bcrypt.hash("Admin@12345", 10);

    await pool.query(
      `INSERT INTO users(username,password,role)
       VALUES($1,$2,$3)`,
      ["admin", hash, "Admin"]
    );
  }
}

/* ================= AUTH ================= */

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    const token = header.replace("Bearer ", "");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid login session" });
  }
}

function allow(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "You do not have permission"
      });
    }
    next();
  };
}

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Wrong username or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "Wrong username or password"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

/* ================= DASHBOARD ================= */

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN type='income'
          THEN amount ELSE 0 END),0) AS income,
        COALESCE(SUM(CASE WHEN type='expense'
          THEN amount ELSE 0 END),0) AS expense,
        COUNT(*) AS transactions
      FROM transactions
    `);

    const row = result.rows[0];

    const income = Number(row.income);
    const expense = Number(row.expense);

    res.json({
      income,
      expense,
      profit: income - expense,
      transactions: Number(row.transactions)
    });

  } catch {
    res.status(500).json({ error: "Dashboard error" });
  }
});

/* ================= TRANSACTIONS ================= */

app.get("/api/transactions", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM transactions
      ORDER BY date DESC, id DESC
    `);

    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Could not load transactions" });
  }
});

/* ADD */

app.post(
  "/api/transactions",
  auth,
  allow("Admin", "Accounting"),
  async (req, res) => {
    try {
      const {
        type,
        category,
        description,
        amount,
        date
      } = req.body;

      if (!["income", "expense"].includes(type)) {
        return res.status(400).json({
          error: "Invalid transaction type"
        });
      }

      if (!amount || Number(amount) <= 0) {
        return res.status(400).json({
          error: "Invalid amount"
        });
      }

      await pool.query(
        `INSERT INTO transactions
        (type,category,description,amount,date,created_by)
        VALUES($1,$2,$3,$4,$5,$6)`,
        [
          type,
          category || "",
          description || "",
          Number(amount),
          date || new Date().toISOString().slice(0, 10),
          req.user.username
        ]
      );

      res.json({ success: true });

    } catch {
      res.status(500).json({
        error: "Could not add transaction"
      });
    }
  }
);

/* DELETE */

app.delete(
  "/api/transactions/:id",
  auth,
  allow("Admin"),
  async (req, res) => {
    try {
      await pool.query(
        "DELETE FROM transactions WHERE id=$1",
        [req.params.id]
      );

      res.json({ success: true });

    } catch {
      res.status(500).json({
        error: "Could not delete transaction"
      });
    }
  }
);

/* ================= USERS ================= */

app.get(
  "/api/users",
  auth,
  allow("Admin"),
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT id,username,role,created_at
        FROM users
        ORDER BY id DESC
      `);

      res.json(result.rows);

    } catch {
      res.status(500).json({
        error: "Could not load users"
      });
    }
  }
);

/* CREATE USER */

app.post(
  "/api/users",
  auth,
  allow("Admin"),
  async (req, res) => {
    try {
      const {
        username,
        password,
        role
      } = req.body;

      if (!username || !password) {
        return res.status(400).json({
          error: "Username and password required"
        });
      }

      if (!["Admin", "Accounting", "Viewer"].includes(role)) {
        return res.status(400).json({
          error: "Invalid role"
        });
      }

      const hash = await bcrypt.hash(password, 10);

      await pool.query(
        `INSERT INTO users(username,password,role)
         VALUES($1,$2,$3)`,
        [username, hash, role]
      );

      res.json({ success: true });

    } catch {
      res.status(400).json({
        error: "Username already exists"
      });
    }
  }
);

/* DELETE USER */

app.delete(
  "/api/users/:id",
  auth,
  allow("Admin"),
  async (req, res) => {
    try {
      if (Number(req.params.id) === req.user.id) {
        return res.status(400).json({
          error: "You cannot delete yourself"
        });
      }

      await pool.query(
        "DELETE FROM users WHERE id=$1",
        [req.params.id]
      );

      res.json({ success: true });

    } catch {
      res.status(500).json({
        error: "Could not delete user"
      });
    }
  }
);

/* ================= REPORT ================= */

app.get("/api/report", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        date,type,category,description,
        amount,created_by
      FROM transactions
      ORDER BY date DESC,id DESC
    `);

    res.json(result.rows);

  } catch {
    res.status(500).json({
      error: "Could not load report"
    });
  }
});

/* ================= WEBSITE ================= */

app.get("/", (req, res) => {

res.send(`<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>My Business Accounting</title>

<style>

*{box-sizing:border-box}

body{
 margin:0;
 font-family:Arial,sans-serif;
 background:#f4f6f9;
 color:#172033;
}

button,input,select{
 font:inherit;
}

button{
 border:0;
 border-radius:9px;
 padding:11px 16px;
 cursor:pointer;
 background:#1769ff;
 color:#fff;
 font-weight:bold;
}

button:hover{
 opacity:.9;
}

.danger{
 background:#e53935;
}

.gray{
 background:#667085;
}

.login{
 min-height:100vh;
 display:flex;
 align-items:center;
 justify-content:center;
 padding:20px;
}

.loginbox{
 width:100%;
 max-width:400px;
 background:#fff;
 padding:30px;
 border-radius:18px;
 box-shadow:0 10px 40px #0002;
}

.loginbox h1{
 text-align:center;
}

input,select{
 width:100%;
 padding:12px;
 border:1px solid #ddd;
 border-radius:9px;
 margin:6px 0 14px;
}

.app{
 display:none;
 min-height:100vh;
}

.sidebar{
 position:fixed;
 top:0;
 bottom:0;
 left:0;
 width:235px;
 background:#101828;
 color:white;
 padding:20px;
}

.logo{
 font-size:22px;
 font-weight:bold;
 margin-bottom:25px;
}

.nav button{
 width:100%;
 margin:4px 0;
 text-align:left;
 background:transparent;
}

.nav button:hover{
 background:#ffffff18;
}

.main{
 margin-left:235px;
 padding:25px;
}

.top{
 display:flex;
 justify-content:space-between;
 align-items:center;
 margin-bottom:20px;
}

.page{
 display:none;
}

.page.active{
 display:block;
}

.cards{
 display:grid;
 grid-template-columns:repeat(4,1fr);
 gap:18px;
}

.card{
 background:white;
 padding:22px;
 border-radius:15px;
 box-shadow:0 5px 20px #0000000d;
}

.card small{
 color:#667085;
}

.card strong{
 display:block;
 margin-top:10px;
 font-size:27px;
}

.panel{
 background:#fff;
 margin-top:20px;
 padding:22px;
 border-radius:15px;
 box-shadow:0 5px 20px #0000000d;
}

.grid{
 display:grid;
 grid-template-columns:repeat(2,1fr);
 gap:12px;
}

table{
 width:100%;
 border-collapse:collapse;
 margin-top:15px;
}

th,td{
 padding:11px;
 border-bottom:1px solid #eee;
 text-align:left;
}

.income{
 color:#07883b;
 font-weight:bold;
}

.expense{
 color:#d92d20;
 font-weight:bold;
}

.badge{
 padding:5px 9px;
 border-radius:20px;
 background:#eef4ff;
 color:#1769ff;
 font-size:12px;
}

.tablewrap{
 overflow:auto;
}

@media(max-width:800px){

 .sidebar{
  position:relative;
  width:100%;
  height:auto;
 }

 .main{
  margin-left:0;
  padding:15px;
 }

 .cards{
  grid-template-columns:repeat(2,1fr);
 }

}

@media(max-width:500px){

 .cards{
  grid-template-columns:1fr;
 }

 .grid{
  grid-template-columns:1fr;
 }

 .top{
  align-items:flex-start;
  flex-direction:column;
 }

 table{
  font-size:12px;
 }

}

</style>

</head>

<body>

<div class="login" id="loginPage">

 <div class="loginbox">

  <h1>Accounting Login</h1>

  <input
   id="username"
   placeholder="Username">

  <input
   id="password"
   type="password"
   placeholder="Password">

  <button
   style="width:100%"
   onclick="login()">
   Login
  </button>

  <p id="loginError"
  style="color:#d92d20;text-align:center"></p>

 </div>

</div>


<div class="app" id="app">

<aside class="sidebar">

 <div class="logo">
  My Accounting
 </div>

 <div class="nav">

  <button onclick="page('dashboard')">
   📊 Dashboard
  </button>

  <button onclick="page('transactions')">
   💰 Transactions
  </button>

  <button onclick="page('reports')">
   📑 Reports
  </button>

  <button id="usersButton"
  onclick="page('users')">
   👥 Users
  </button>

  <button class="gray"
  onclick="logout()">
   🚪 Logout
  </button>

 </div>

</aside>


<main class="main">

<div class="top">

 <div>
  <h2 id="title">Dashboard</h2>
  <div id="userinfo"></div>
 </div>

</div>


<!-- DASHBOARD -->

<section id="dashboard"
class="page active">

<div class="cards">

 <div class="card">
  <small>Total Income</small>
  <strong id="income">৳0</strong>
 </div>

 <div class="card">
  <small>Total Expense</small>
  <strong id="expense">৳0</strong>
 </div>

 <div class="card">
  <small>Profit / Loss</small>
  <strong id="profit">৳0</strong>
 </div>

 <div class="card">
  <small>Transactions</small>
  <strong id="count">0</strong>
 </div>

</div>

<div class="panel">

<h3>Business Accounting</h3>

<p>
Admin, Accounting এবং Viewer একই
online database ব্যবহার করবে।
</p>

</div>

</section>


<!-- TRANSACTIONS -->

<section id="transactions"
class="page">

<div class="panel" id="addBox">

<h3>Add Transaction</h3>

<div class="grid">

<div>
<label>Type</label>
<select id="type">
<option value="income">Income</option>
<option value="expense">Expense</option>
</select>
</div>

<div>
<label>Category</label>
<input id="category"
placeholder="Sales / Salary / Rent">
</div>

<div>
<label>Description</label>
<input id="description"
placeholder="Description">
</div>

<div>
<label>Amount</label>
<input id="amount"
type="number"
placeholder="Amount">
</div>

<div>
<label>Date</label>
<input id="date"
type="date">
</div>

</div>

<button onclick="addTransaction()">
Add Transaction
</button>

</div>


<div class="panel">

<h3>All Transactions</h3>

<div class="tablewrap">

<table>

<thead>
<tr>
<th>Date</th>
<th>Type</th>
<th>Category</th>
<th>Description</th>
<th>Amount</th>
<th>User</th>
<th>Action</th>
</tr>
</thead>

<tbody id="transactionsTable"></tbody>

</table>

</div>

</div>

</section>


<!-- REPORT -->

<section id="reports"
class="page">

<div class="panel">

<h3>Financial Report</h3>

<button onclick="csv()">
Download CSV
</button>

<div class="tablewrap">

<table>

<thead>
<tr>
<th>Date</th>
<th>Type</th>
<th>Category</th>
<th>Description</th>
<th>Amount</th>
<th>User</th>
</tr>
</thead>

<tbody id="reportTable"></tbody>

</table>

</div>

</div>

</section>


<!-- USERS -->

<section id="users"
class="page">

<div class="panel">

<h3>Create User</h3>

<div class="grid">

<div>
<label>Username</label>
<input id="newUser">
</div>

<div>
<label>Password</label>
<input id="newPass"
type="password">
</div>

<div>
<label>Role</label>
<select id="newRole">
<option>Admin</option>
<option>Accounting</option>
<option>Viewer</option>
</select>
</div>

</div>

<button onclick="createUser()">
Create User
</button>

</div>


<div class="panel">

<h3>User List</h3>

<div class="tablewrap">

<table>

<thead>
<tr>
<th>ID</th>
<th>Username</th>
<th>Role</th>
<th>Action</th>
</tr>
</thead>

<tbody id="usersTable"></tbody>

</table>

</div>

</div>

</section>

</main>

</div>


<script>

let token=localStorage.getItem("token");
let me=JSON.parse(
 localStorage.getItem("me")||"null"
);

const $=id=>document.getElementById(id);

function money(n){
 return "৳"+Number(n||0)
 .toLocaleString("en-BD",{
  minimumFractionDigits:2
 });
}

async function api(url,opt={}){

 opt.headers={
  "Content-Type":"application/json",
  ...(opt.headers||{}),
  Authorization:"Bearer "+token
 };

 const r=await fetch(url,opt);
 const d=await r.json();

 if(!r.ok){
  if(r.status===401) logout();
  throw new Error(d.error||"Error");
 }

 return d;
}


/* LOGIN */

async function login(){

 try{

  const r=await fetch("/api/login",{
   method:"POST",
   headers:{
    "Content-Type":"application/json"
   },
   body:JSON.stringify({
    username:$("username").value.trim(),
    password:$("password").value
   })
  });

  const d=await r.json();

  if(!r.ok)
   throw new Error(d.error);

  token=d.token;
  me=d.user;

  localStorage.setItem("token",token);
  localStorage.setItem("me",JSON.stringify(me));

  start();

 }catch(e){

  $("loginError").innerText=e.message;

 }

}


/* START */

function start(){

 $("loginPage").style.display="none";
 $("app").style.display="block";

 $("userinfo").innerHTML=
 me.username+
 " · <span class='badge'>"+
 me.role+
 "</span>";

 if(me.role!=="Admin"){
  $("usersButton").style.display="none";
 }

 if(me.role==="Viewer"){
  $("addBox").style.display="none";
 }

 dashboard();

}


/* PAGE */

function page(name){

 document.querySelectorAll(".page")
 .forEach(x=>x.classList.remove("active"));

 $(name).classList.add("active");

 const titles={
  dashboard:"Dashboard",
  transactions:"Transactions",
  reports:"Reports",
  users:"User Management"
 };

 $("title").innerText=titles[name];

 if(name==="dashboard") dashboard();
 if(name==="transactions") transactions();
 if(name==="reports") reports();
 if(name==="users") users();

}


/* DASHBOARD */

async function dashboard(){

 const d=await api("/api/dashboard");

 $("income").innerText=money(d.income);
 $("expense").innerText=money(d.expense);
 $("profit").innerText=money(d.profit);
 $("count").innerText=d.transactions;

}


/* TRANSACTIONS */

async function transactions(){

 const rows=await api("/api/transactions");

 $("transactionsTable").innerHTML=
 rows.map(x=>`

<tr>

<td>${x.date}</td>

<td class="${x.type}">
 ${x.type}
</td>

<td>${safe(x.category)}</td>

<td>${safe(x.description)}</td>

<td>${money(x.amount)}</td>

<td>${safe(x.created_by)}</td>

<td>
${
 me.role==="Admin"
 ? `<button class="danger"
 onclick="delTransaction(${x.id})">
 Delete
 </button>`
 : "-"
}
</td>

</tr>

`).join("");

}


/* ADD */

async function addTransaction(){

 const data={
  type:$("type").value,
  category:$("category").value,
  description:$("description").value,
  amount:$("amount").value,
  date:$("date").value
 };

 if(!data.amount){
  alert("Amount দিন");
  return;
 }

 try{

  await api("/api/transactions",{
   method:"POST",
   body:JSON.stringify(data)
  });

  $("amount").value="";
  $("description").value="";

  alert("Transaction added");

  transactions();
  dashboard();

 }catch(e){
  alert(e.message);
 }

}


/* DELETE */

async function delTransaction(id){

 if(!confirm("Delete করবেন?")) return;

 try{

  await api("/api/transactions/"+id,{
   method:"DELETE"
  });

  transactions();
  dashboard();

 }catch(e){
  alert(e.message);
 }

}


/* REPORT */

async function reports(){

 const rows=await api("/api/report");

 window.report=rows;

 $("reportTable").innerHTML=
 rows.map(x=>`

<tr>

<td>${x.date}</td>

<td class="${x.type}">
 ${x.type}
</td>

<td>${safe(x.category)}</td>

<td>${safe(x.description)}</td>

<td>${money(x.amount)}</td>

<td>${safe(x.created_by)}</td>

</tr>

`).join("");

}


/* CSV */

function csv(){

 const rows=window.report||[];

 let out=
 "Date,Type,Category,Description,Amount,User\\n";

 rows.forEach(x=>{

  out += [
   x.date,
   x.type,
   x.category,
   x.description,
   x.amount,
   x.created_by
  ].map(v=>
   '"'+String(v||"")
   .replaceAll('"','""')+'"'
  ).join(",")+"\\n";

 });

 const blob=new Blob([out],{
  type:"text/csv"
 });

 const a=document.createElement("a");

 a.href=URL.createObjectURL(blob);
 a.download="accounting-report.csv";
 a.click();

}


/* USERS */

async function users(){

 if(me.role!=="Admin") return;

 const rows=await api("/api/users");

 $("usersTable").innerHTML=
 rows.map(x=>`

<tr>

<td>${x.id}</td>

<td>${safe(x.username)}</td>

<td>
<span class="badge">
${safe(x.role)}
</span>
</td>

<td>
${
 x.id!==me.id
 ?
 `<button class="danger"
 onclick="delUser(${x.id})">
 Delete
 </button>`
 :
 "Current User"
}
</td>

</tr>

`).join("");

}


/* CREATE USER */

async function createUser(){

 const username=$("newUser").value.trim();
 const password=$("newPass").value;
 const role=$("newRole").value;

 if(!username||!password){
  alert("Username এবং Password দিন");
  return;
 }

 try{

  await api("/api/users",{
   method:"POST",
   body:JSON.stringify({
    username,
    password,
    role
   })
  });

  $("newUser").value="";
  $("newPass").value="";

  alert("User created");

  users();

 }catch(e){
  alert(e.message);
 }

}


/* DELETE USER */

async function delUser(id){

 if(!confirm("User delete করবেন?")) return;

 try{

  await api("/api/users/"+id,{
   method:"DELETE"
  });

  users();

 }catch(e){
  alert(e.message);
 }

}


/* HTML SECURITY */

function safe(v){

 return String(v||"")
 .replaceAll("&","&amp;")
 .replaceAll("<","&lt;")
 .replaceAll(">","&gt;")
 .replaceAll('"',"&quot;")
 .replaceAll("'","&#039;");

}


/* LOGOUT */

function logout(){

 localStorage.removeItem("token");
 localStorage.removeItem("me");

 location.reload();

}


/* AUTO LOGIN */

if(token&&me) start();

</script>

</body>
</html>`);

});


/* ================= START ================= */

initDB()
.then(() => {

  app.listen(PORT, () => {
    console.log(
      "Accounting website running on port " + PORT
    );
  });

})
.catch(err => {

  console.error("Database error:", err);
  process.exit(1);

});
