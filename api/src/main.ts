import express from "express";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (_, res) => {
  res.json({ status: "ok" });
});

app.get("/user/connection", (_, res) => {
    res.json({})
});

app.listen(3000, () => {});
