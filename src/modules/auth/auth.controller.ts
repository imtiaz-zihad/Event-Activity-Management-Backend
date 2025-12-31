import { Request, Response } from "express";
import { AuthService } from "./auth.service";

const register = async (req: Request, res: Response) => {
  const user = await AuthService.registerUser(req.body);

  res.status(201).json({
    success: true,
    message: "User registered",
    data: user,
  });
};

const login = async (req: Request, res: Response) => {
  const token = await AuthService.loginUser(
    req.body.email,
    req.body.password
  );

  res.status(200).json({
    success: true,
    message: "Login successful",
    data: token,
  });
};

export const AuthController = {
  register,
  login,
};
