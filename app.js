const express = require("express");
const cors = require("cors");
const userRoutes = require("./routes/userRoutes");

const app = express();
app.use(express.json());
app.use(cors());

app.use("/api/users", userRoutes);

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
