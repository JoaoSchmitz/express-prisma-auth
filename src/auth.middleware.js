/**
 * Cria a fábrica de middlewares de autenticação e autorização.
 * @param {object} dependencies - As dependências injetadas.
 * @param {PrismaClient} dependencies.prismaClient - A instância do Prisma.
 * @param {object} dependencies.helpers - Os helpers de hashing e token.
 * @returns {object} O objeto contendo os middlewares.
 */
export function createAuthMiddleware(prismaClient, helpers) {
  /**
   * Middleware de AUTENTICAÇÃO.
   * Verifica se o usuário está logado via JWT (Access Token).
   * Injeta req.user se for válido.
   */
  const ensureAuthenticated = async (req, res, next) => {
    try {
      const { authorization } = req.headers;

      if (!authorization) {
        return res.status(401).json({ message: "Token não fornecido." });
      }

      // Verifica se o formato é "Bearer [token]"
      const parts = authorization.split(" ");
      if (parts.length !== 2 || parts[0] !== "Bearer") {
        return res
          .status(401)
          .json({
            message: "Token malformado. Formato esperado: 'Bearer <token>'.",
          });
      }
      const token = parts[1];

      const payload = helpers.verifyAccessToken(token);
      if (!payload) {
        return res.status(401).json({ message: "Token inválido ou expirado." });
      }

      // Verifica se o usuário do token ainda existe no banco
      const usuario = await prismaClient.usuario.findUnique({
        where: { id: payload.id },
        select: { id: true, email: true, cargo: true },
      });

      if (!usuario) {
        return res
          .status(401)
          .json({ message: "Usuário do token não encontrado." });
      }

      // INJETA o usuário na requisição
      req.user = usuario;
      return next();
    } catch (error) {
      console.error("[AuthMiddleware Error] ensureAuthenticated:", error);
      return res
        .status(500)
        .json({ message: "Erro interno no servidor durante a autenticação." });
    }
  };

  /**
   * Factory de Middleware de AUTORIZAÇÃO.
   * Deve ser usado *APÓS* o ensureAuthenticated.
   * @param {string[]} allowedRoles - Um array de cargos permitidos (ex: ['ADMIN', 'FUNCIONARIO'])
   */
  const ensureRole = (allowedRoles) => {
    return (req, res, next) => {
      // 1. Garante que o middleware 'ensureAuthenticated' rodou antes
      if (!req.user || !req.user.cargo) {
        return res.status(401).json({
          message:
            "Usuário não autenticado. O middleware ensureRole deve ser usado após o ensureAuthenticated.",
        });
      }

      const { cargo } = req.user;

      // 2. Verifica se o cargo do usuário está na lista de cargos permitidos
      if (allowedRoles.includes(cargo)) {
        return next(); // Usuário tem permissão
      }

      // 3. Usuário está logado, mas não tem o cargo necessário
      return res.status(403).json({
        message: "Acesso negado. Você não tem permissão para este recurso.",
      });
    };
  };

  return {
    ensureAuthenticated,
    ensureRole,
  };
}
