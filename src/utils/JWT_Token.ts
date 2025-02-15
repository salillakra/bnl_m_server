import * as jose from "jose";

// This function verifies the provided JWT token and returns the payload if valid.
export const VerifyToken = async (token: string) => {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET);
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }
  try {
    const { payload } = await jose.jwtVerify(token, secret);
    return { payload };
  } catch (error) {
    console.error("Token verification error:", error);
    throw new Error("Invalid token");
  }
};

interface TokenPayload extends jose.JWTPayload {
  memberId: string;
}

interface TokenData {
  accessToken: string;
  refreshToken: string;
}

// This function generates an access token and a refresh token using the provided data.
export const getToken = async (data: TokenPayload): Promise<TokenData> => {
  const payload: TokenPayload = {
    memberId: data.memberId,
  };

  const secret = new TextEncoder().encode(process.env.JWT_SECRET);

  const alg = "HS256";

  const accessToken = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime("1d")
    .sign(secret);

  const refreshToken = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime("10d")
    .sign(secret);

  return { accessToken, refreshToken };
};
