// module.exports = {
//   host: "localhost",
//   user: "root",
//   password: "",
//   database: "nodedb",
// };

const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "nodedb",
});

module.exports = pool;
