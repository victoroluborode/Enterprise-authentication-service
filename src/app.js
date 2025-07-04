const express = require('express');
const app = express();
require('dotenv').config();

app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
})

module.exports = app;