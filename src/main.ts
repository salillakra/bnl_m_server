import express from "express";
import { Request, Response } from "express";
import { getToken, VerifyToken } from "./utils/JWT_Token";
import { PrismaClient } from "@prisma/client";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { authenticateTokenMiddleware } from "./utils/middleware";

dotenv.config();

const PORT = process.env.PORT || 3000;
const prisma = new PrismaClient();
const app = express();
app.use(express.json());
app.use(cors());

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World");
});

app.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId, password }: { userId?: string; password?: string } =
      req.body;

    if (!userId || !password) {
      res.status(400).json({ message: "User ID and password are required" });
    }

    const member = await prisma.memberCredentials.findFirst({
      where: { userId },
      select: { id: true, password: true, memberId: true },
    });

    if (!member) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const [isValid, token] = await Promise.all([
      bcrypt.compare(password!, member.password),
      getToken({ memberId: member.memberId }),
    ]);

    if (!isValid) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    await prisma.memberCredentials.update({
      where: { id: member.id },
      data: { refreshToken: token.refreshToken },
    });

    res.status(200).json({ message: "Success", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post(
  "/getaccount",
  authenticateTokenMiddleware,
  async (req: Request, res: Response): Promise<void> => {
    const { memberId } = req.body;

    if (!memberId) {
      res.status(400).send("Member ID is required");
    }

    const account = await prisma.customerAccount.findFirst({
      where: {
        memberId: memberId,
      },
    });

    if (!account) {
      res.status(404).send("Account not found");
    }

    res.json(account);
  }
);

//refresh token
app.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    res.status(400).send("Refresh token is required");
    return;
  }

  try {
    const { payload } = await VerifyToken(refreshToken);

    const member = await prisma.memberCredentials.findFirst({
      where: {
        memberId: payload.memberId as string,
      },
    });

    if (!member) {
      res.status(404).send("Member not found");
      return;
    }

    if (refreshToken !== member.refreshToken) {
      res.status(403).send("Forbidden: Invalid refresh token");
      return;
    }

    const token = await getToken({ memberId: member.memberId });
    res
      .status(200)
      .json({ message: "success", accessToken: token.accessToken });
  } catch (err) {
    console.error(err);
    res.status(403).json({ message: "Forbidden: Invalid token" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
