import express from "express";
import { PrismaClient } from "@prisma/client";
import { Logger } from "tslog";
import crypto from "crypto";

// Create a new instance of the logger
const console = new Logger();
process.on("uncaughtException", (error) => console.error(error));

// Prisma
const Prisma = new PrismaClient();

// Create a new express application
const App = express();
const RouterV01Beta = express.Router();
App.use(express.json());
App.use(express.urlencoded({ extended: true }));

App.use("/v0.1-beta", RouterV01Beta);

RouterV01Beta.get("/", async (req, res) => {
  res.json({
    version: "v0.1beta",
  });
});

RouterV01Beta.get("/signup", async (req, res) => {
  try {
    // Get Authorization
    const Authorization = req.headers.authorization;
    const AuthorizationSplit = Authorization?.split(" ");
    const User =
      AuthorizationSplit &&
      AuthorizationSplit.length == 2 &&
      AuthorizationSplit[0] == "Bearer"
        ? await Prisma.user.findUnique({
            where: { bearer: AuthorizationSplit[1] },
          })
        : null;

    // Create User
    if (!User) {
      const NewUser = await Prisma.user.create({
        data: {
          username: crypto.randomBytes(16).toString("hex"),
          bearer: crypto.randomBytes(64).toString("hex"),
        },
      });

      // Send Response
      res.status(200).json({
        username: NewUser.username,
        bearer: NewUser.bearer,
      });
      return;
    }

    // Send Response
    res.status(200).json({
      username: User.username,
      bearer: User.bearer,
    });
    return;
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal server error" });
  }
});

RouterV01Beta.get("/user", async (req, res) => {
  try {
    // Get Authorization
    const Authorization = req.headers.authorization;
    const AuthorizationSplit = Authorization?.split(" ");
    const User =
      AuthorizationSplit &&
      AuthorizationSplit.length == 2 &&
      AuthorizationSplit[0] == "Bearer"
        ? await Prisma.user.findUnique({
            where: { bearer: AuthorizationSplit[1] },
          })
        : null;
    if (!User) {
      res
        .status(401)
        .json({ code: "Unauthorized", message: "Invalid bearer token" });
      return;
    }

    // Send Response
    res.status(200).json({
      username: User.username,
    });
    return;
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal server error" });
  }
});

RouterV01Beta.put("/user", async (req, res) => {
  // Validate Content-Type
  if (req.headers["content-type"] !== "application/json") {
    res.status(406).json({
      error: "UnsupportedType",
      message: "Only application/json is supported",
    });
    return;
  }

  try {
    // Get Authorization
    const Authorization = req.headers.authorization;
    const AuthorizationSplit = Authorization?.split(" ");
    const User =
      AuthorizationSplit &&
      AuthorizationSplit.length == 2 &&
      AuthorizationSplit[0] == "Bearer"
        ? await Prisma.user.findUnique({
            where: { bearer: AuthorizationSplit[1] },
          })
        : null;
    if (!User) {
      res
        .status(401)
        .json({ code: "Unauthorized", message: "Invalid bearer token" });
      return;
    }

    // Validate Parameters
    if (!req.body["username"]) {
      res
        .status(400)
        .json({ code: "BadRequest", message: "Invalid Parameters" });
      return;
    }

    // Update User
    const UpdateUser = await Prisma.user.update({
      where: {
        id: User.id,
      },
      data: {
        username: String(req.body["username"]),
      },
    });

    // Send Response
    res.status(200).json({
      username: UpdateUser.username,
    });
    return;
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal server error" });
  }
});

RouterV01Beta.get("/user/config", async (req, res) => {
  try {
    // Get Authorization
    const Authorization = req.headers.authorization;
    const AuthorizationSplit = Authorization?.split(" ");
    const User =
      AuthorizationSplit &&
      AuthorizationSplit.length == 2 &&
      AuthorizationSplit[0] == "Bearer"
        ? await Prisma.user.findUnique({
            where: { bearer: AuthorizationSplit[1] },
            select: { id: true, peer: true },
          })
        : null;
    if (!User) {
      res
        .status(401)
        .json({ code: "Unauthorized", message: "Invalid bearer token" });
      return;
    }

    // Get Peers
    const Peers = await Prisma.peer.findMany({
      where: { userId: { not: User.id } },
    });

    // Send Response
    res.status(200).json({
      public_key: User.peer?.publicKey ?? "",
      endpoint: User.peer?.endpoint ?? "",
      peers: Peers.map((peer) => ({
        publick_key: peer.publicKey,
        endpoint: peer.endpoint,
        allowed_ips: [`10.0.0.${peer.userId}/32`],
        persistent_keepalive: 20,
      })),
    });
    return;
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal server error" });
  }
});

RouterV01Beta.post("/user/config", async (req, res) => {
  // Validate Content-Type
  if (req.headers["content-type"] !== "application/json") {
    res.status(406).json({
      error: "UnsupportedType",
      message: "Only application/json is supported",
    });
    return;
  }

  try {
    // Get Authorization
    const Authorization = req.headers.authorization;
    const AuthorizationSplit = Authorization?.split(" ");
    const User =
      AuthorizationSplit &&
      AuthorizationSplit.length == 2 &&
      AuthorizationSplit[0] == "Bearer"
        ? await Prisma.user.findUnique({
            where: { bearer: AuthorizationSplit[1] },
            select: { id: true, peer: true },
          })
        : null;
    if (!User) {
      res
        .status(401)
        .json({ code: "Unauthorized", message: "Invalid bearer token" });
      return;
    }

    // Validate Parameters
    const RegexPublicKey = /^[a-z0-9]{64}$/;
    const RegexEndpoint =
      /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}$/;
    if (
      !req.body["public_key"] ||
      !req.body["endpoint"] ||
      !RegexPublicKey.test(String(req.body["public_key"])) ||
      !RegexEndpoint.test(String(req.body["endpoint"]))
    ) {
      res.status(400).json({
        code: "BadRequest",
        message: "Invalid Parameters",
      });
      return;
    }

    // Create or Update Peer
    const Peer =
      User.peer === null
        ? await Prisma.peer.create({
            data: {
              publicKey: String(req.body["public_key"]),
              endpoint: String(req.body["endpoint"]),
              allowedIps: `10.0.0.${User.id}/32`,
              persistentKeepaliveInterval: 25,
              user: {
                connect: {
                  id: User.id,
                },
              },
            },
          })
        : await Prisma.peer.update({
            where: {
              id: User.peer.id,
            },
            data: {
              publicKey: String(req.body["public_key"]),
              endpoint: String(req.body["endpoint"]),
              allowedIps: `10.0.0.${User.id}/32`,
              persistentKeepaliveInterval: 25,
            },
          });

    // Get Peers
    const Peers = await Prisma.peer.findMany({
      where: { userId: { not: User.id } },
    });

    // Send Response
    res.status(200).json({
      public_key: Peer.publicKey,
      endpoint: Peer.endpoint,
      peers: Peers.map((peer) => ({
        public_key: peer.publicKey,
        endpoint: peer.endpoint,
        allowed_ips: [`10.0.0.${peer.userId}/32`],
        persistent_keepalive: 20,
      })),
    });
    return;
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal server error" });
  }
});

App.all("*", (_, res) => {
  res.status(404).json({ error: "Not found" });
});

App.listen(3000, () => {
  Prisma.$connect();
});
