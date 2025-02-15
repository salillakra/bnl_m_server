import { Request, Response, NextFunction } from "express";
import { VerifyToken } from "./JWT_Token";

export const authenticateTokenMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader: string | undefined = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Unauthorized: No token provided" });
    return;
  }

  const token: string = authHeader.split(" ")[1];

  try {
    const { payload }: { payload: any } = await VerifyToken(token);
    req.body = payload;
    next();
  } catch (err) {
    console.error("Authentication error:", err);
    res.status(403).json({ message: "Forbidden: Invalid token" });
  }
};
