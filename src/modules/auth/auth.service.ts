import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../../config/prisma";

interface RegisterPayload {
  fullName: string;
  email: string;
  password: string;
  role?: "USER" | "HOST";
}

const registerUser = async (payload: RegisterPayload) => {
  const existingUser = await prisma.user.findUnique({
    where: { email: payload.email },
  });

  if (existingUser) {
    throw new Error("Email already registered");
  }

  const hashedPassword = await bcrypt.hash(payload.password, 10);

  const user = await prisma.user.create({
    data: {
      email: payload.email,
      password: hashedPassword,
      role: payload.role ?? "USER",
      profile: {
        create: {
          fullName: payload.fullName,
        },
      },
    },
    include: {
      profile: true,
    },
  });

  const { password, ...safeUser } = user;
  return safeUser;
};

const loginUser = async (email: string, password: string) => {
  const user = await prisma.user.findUnique({
    where: { email },
    include: { profile: true },
  });

  if (!user) {
    throw new Error("User not found");
  }

  if (user.isBlocked) {
    throw new Error("User is blocked by admin");
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new Error("Invalid email or password");
  }

  const token = jwt.sign(
    {
      id: user.id,
      role: user.role,
      email: user.email,
    },
    process.env.JWT_SECRET as string,
    { expiresIn: "7d" }
  );

  const { password: _, ...safeUser } = user;

  return {
    token,
    user: safeUser,
  };
};

export const AuthService = {
  registerUser,
  loginUser,
};
