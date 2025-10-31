import { Router } from "express";
import cookieParser from "cookie-parser";

// Recebe o controller e o middleware
export function createAuthRoutes(authController, authMiddleware) {
  const router = Router();

  // Usa o cookieParser APENAS para as rotas de autenticação
  router.use(cookieParser());

  // Rotas públicas
  router.post("/register", authController.handleRegister);
  router.post("/login", authController.handleLogin);
  router.post("/refresh-token", authController.handleRefreshToken);
  router.post(
    "/request-password-reset",
    authController.handleRequestPasswordReset
  );
  router.post("/reset-password", authController.handleResetPassword);

  // Rotas de verificação (que vêm de links de email)
  router.get("/verify-email", authController.handleVerifyEmail);
  router.get("/verify-email-update", authController.handleVerifyEmailUpdate);

  // --- Rotas Protegidas ---
  // (Exigem que o 'ensureAuthenticated' rode antes)
  router.post(
    "/logout",
    authMiddleware.ensureAuthenticated,
    authController.handleLogout
  );
  router.post(
    "/request-email-update",
    authMiddleware.ensureAuthenticated,
    authController.handleRequestEmailUpdate
  );
  router.patch(
    "/update-password",
    authMiddleware.ensureAuthenticated,
    authController.handleUpdatePassword
  );

  // Rota de exemplo para testar o middleware
  router.get("/me", authMiddleware.ensureAuthenticated, (req, res) => {
    res.status(200).json(req.user);
  });

  return router;
}
