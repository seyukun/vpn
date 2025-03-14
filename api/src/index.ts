import express from "express";
import { PrismaClient } from "@prisma/client";
import { Logger } from "tslog";

// Create a new instance of the logger
const console = new Logger();
process.on("uncaughtException", (error) => console.error(error));

// Prisma
const prisma = new PrismaClient();

// Create a new express application
const app = express();
const routerV1 = express.Router();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/v1", routerV1);

routerV1.get("/", (_, res) => {
  res.json({ status: "ok" });
});

routerV1.get("/user/connection", async (req, res, next) => {
  console.debug(req.path, req.headers);
  if (
    !req.headers.authorization ||
    req.headers.authorization.startsWith("Bearer ")
  ) {
    res.status(401).json({ error: "Unauthorized" });
  } else if (
    !req.headers["content-type"] ||
    req.headers["content-type"] !== "application/json"
  ) {
    res.status(400).json({ error: "Bad Request" });
  } else {
    const session = await prisma.session.findUnique({
      where: { authorization: req.headers.authorization },
      include: {
        User: {
          include: {
            Networks: {
              include: {
                Users: {
                  include: {
                    Sessions: {
                      include: {
                        Peer: {
                          include: {
                            Session: {
                              include: {
                                User: { include: { Networks: true } },
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        Peer: true,
      },
    });
    if (!session) {
      res.status(401).json({ error: "Unauthorized" });
    } else {
      const peers = [
        ...new Set(
          session.User.Networks.flatMap((network) =>
            network.Users.flatMap((user) =>
              user.Sessions.filter((sess) => sess.id != session.id).map(
                (sess) => sess.Peer
              )
            ).filter((user) => !!user)
          ).filter((network) => !!network)
        ),
      ];

      let config = "";
      if (session.Peer) {
        config += `private_key=${session.Peer.privateKey}\n`;
        config += `listen_port=${session.Peer.endpoint.split(":")[1]}\n`;
      }
      peers.forEach((peer) => {
        const allowed_ip = [
          ...new Set(
            peer.Session.User.Networks.flatMap((network) => network.ipRange)
          ),
        ];
        config += `public_key=${peer.publicKey}\n`;
        config += `endpoint=${peer.endpoint}\n`;
        config += `allowed_ip=${allowed_ip.join(",")}\n`;
        config += `persistent_keepalive_interval=${peer.persistentKeepaliveInterval}\n`;
      });
      res.json({ config: config });
    }
    next();
  }
});

app.all("*", (_, res) => {
  res.status(404).json({ error: "Not found" });
});

app.listen(3000, () => {
  prisma.$connect();
});
