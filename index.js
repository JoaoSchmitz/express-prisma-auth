// express-prisma-auth/src/index.js
import { createAuthHelpers } from "./src/auth.helpers.js";
import { createAuthService } from "./src/auth.service.js";
import { createAuthMiddleware } from "./src/auth.middleware.js";
import { createAuthController } from "./src/auth.controller.js";
import { createAuthRoutes } from "./src/auth.routes.js";

/**
 * Cria e configura o módulo de autenticação completo.
 * @param {object} config - Objeto de configuração.
 * @param {PrismaClient} config.prismaClient - A instância do PrismaClient.
 * @param {string} config.jwtSecret - Segredo para Access Tokens.
 * @param {any} config.defaultUserRole - O valor do enum RoleUsuario para novos registros.
 * @param {object} config.emailService - Objeto com funções para enviar emails.
 * @param {object} config.urls - URLs do frontend para redirecionamento.
 * @param {string} config.urls.emailVerifySuccess - URL de sucesso após verificar email.
 * @param {string} config.urls.emailVerifyError - URL de falha ao verificar email.
 * @param {string} config.urls.passwordResetSuccess - URL de sucesso após redefinir senha.
 * @param {string} config.urls.emailUpdateSuccess - URL de sucesso após atualizar email.
 * @param {string} [config.jwtExpiresIn='15m'] - Expiração do Access Token.
 * @param {function(tx, newUser): Promise<void>} [config.onUserRegistered] - Hook opcional.
 */
export function createAuthModule({
  prismaClient,
  jwtSecret,
  defaultUserRole,
  emailService,
  urls,
  jwtExpiresIn = "15m",
  onUserRegistered = null,
}) {
  // Validação das novas dependências
  if (!prismaClient) throw new Error("AuthModule: prismaClient é obrigatório.");
  if (!jwtSecret) throw new Error("AuthModule: jwtSecret é obrigatório.");
  if (!defaultUserRole)
    throw new Error("AuthModule: defaultUserRole é obrigatório.");
  if (!emailService) throw new Error("AuthModule: emailService é obrigatório.");
  if (!urls || !urls.emailVerifySuccess || !urls.passwordResetSuccess) {
    throw new Error(
      "AuthModule: config.urls (com pelo menos emailVerifySuccess e passwordResetSuccess) é obrigatório."
    );
  }

  const authHelpers = createAuthHelpers({
    jwtSecret,
    jwtExpiresIn,
  });

  const authService = createAuthService({
    prismaClient,
    helpers: authHelpers,
    emailService,
    defaultUserRole,
    onUserRegistered,
  });

  const authMiddleware = createAuthMiddleware({
    prismaClient,
    helpers: authHelpers,
  });

  // Injeta o 'urls' no controller para que ele saiba para onde redirecionar
  const authController = createAuthController(authService, urls);

  const authRoutes = createAuthRoutes(authController, authMiddleware);

  return {
    authRoutes,
    authMiddleware,
    authService,
  };
}
