import { Request, Response, NextFunction } from "express";
import { verifyToken, JwtUserPayload } from "../../utils/jwt";
import { ApiError } from "../../utils/ApiError";

export interface AuthRequest extends Request {
  user?: JwtUserPayload;
}

// 🔹 Helper: extract token safely
const getTokenFromHeader = (req: Request): string | null => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  const [type, token] = authHeader.split(" ");
  return type === "Bearer" && token ? token : null;
};

// 🔐 AUTHENTICATION
export const auth = (
  req: AuthRequest,
  _res: Response,
  next: NextFunction
) => {
  const token = getTokenFromHeader(req);

  if (!token) {
    return next(new ApiError(401, "Unauthorized: Token missing"));
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch {
    next(new ApiError(401, "Unauthorized: Invalid or expired token"));
  }
};

export const authorizeRole =
  (...allowedRoles: string[]) =>
  (req: AuthRequest, _res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new ApiError(401, "Unauthorized"));
    }

    if (!allowedRoles.includes(req.user.role)) {
      return next(
        new ApiError(403, "Forbidden: You do not have permission")
      );
    }

    next();
  };
