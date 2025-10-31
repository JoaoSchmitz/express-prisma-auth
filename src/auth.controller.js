/**
 * Cria a fábrica de controllers de autenticação.
 * @param {object} authService - O serviço de autenticação injetado.
 * @param {object} urls - O objeto de URLs do frontend injetado.
 * @returns {object} O objeto de controller.
 */
export function createAuthController(authService, urls) {
  /**
   * (Interno) Lida com erros de fluxos baseados em redirecionamento.
   * Loga o erro real, mas redireciona o usuário com uma mensagem genérica e segura.
   */
  const handleRedirectError = (res, error, errorRedirectUrl) => {
    // Log do erro real no servidor para depuração
    console.error(`[AUTH_ERROR]: ${error.message}`);

    // Para erros "seguros" (que o usuário pode ver)
    if (
      error.message.includes("Token inválido") ||
      error.message.includes("expirado") ||
      error.message.includes("já utilizado")
    ) {
      // Redireciona com uma mensagem de erro genérica
      return res.redirect(`${errorRedirectUrl}?error=invalid_token`);
    }

    // Para outros erros de sistema
    return res.redirect(`${errorRedirectUrl}?error=server_error`);
  };

  return {
    /**
     * @route POST /register
     * Lida com o registro de um novo usuário.
     */
    handleRegister: async (req, res) => {
      try {
        const { nome, email, senha } = req.body;
        if (!nome || !email || !senha) {
          return res.status(400).json({
            message: "Nome, email e senha são obrigatórios.",
          });
        }

        const usuario = await authService.register(req.body);
        return res.status(201).json(usuario);
      } catch (error) {
        if (error.message.includes("Email já cadastrado")) {
          return res.status(400).json({ message: error.message });
        }
        return res.status(500).json({
          message: "Erro ao registrar usuário.",
          error: error.message,
        });
      }
    },

    /**
     * @route GET /verify-email
     * Lida com a verificação de email a partir de um token.
     */
    handleVerifyEmail: async (req, res) => {
      try {
        const { token } = req.query;
        await authService.verifyEmail(token);

        // Redireciona para a URL de sucesso injetada
        return res.redirect(urls.emailVerifySuccess);
      } catch (error) {
        // Usa o handler de erro de redirecionamento
        return handleRedirectError(res, error, urls.emailVerifyError);
      }
    },

    /**
     * @route POST /login
     * Autentica um usuário e retorna accessToken e refreshToken (em cookie).
     */
    handleLogin: async (req, res) => {
      try {
        const { email, senha } = req.body;
        if (!email || !senha) {
          return res
            .status(400)
            .json({ message: "Email e senha são obrigatórios." });
        }

        const { accessToken, refreshToken } = await authService.login(req.body);

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 1000 * 60 * 60 * 24 * 7, // 7 dias
        });

        return res.status(200).json({ accessToken });
      } catch (error) {
        if (
          error.message.includes("Credenciais inválidas") ||
          error.message.includes("verifique seu email")
        ) {
          return res.status(401).json({ message: error.message });
        }
        return res
          .status(500)
          .json({ message: "Erro ao fazer login.", error: error.message });
      }
    },

    /**
     * @route POST /logout
     * Efetua o logout invalidando o refresh token.
     */
    handleLogout: async (req, res) => {
      try {
        const refreshToken = req.cookies?.refreshToken;
        if (refreshToken) {
          await authService.logout(refreshToken);
        }

        res.clearCookie("refreshToken", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
        });

        return res.status(204).send();
      } catch (error) {
        // O logout NUNCA deve falhar para o usuário.
        res.clearCookie("refreshToken");
        return res.status(204).send();
      }
    },

    /**
     * @route POST /refresh-token
     * Emite um novo access token usando um refresh token válido (do cookie).
     */
    handleRefreshToken: async (req, res) => {
      try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) {
          return res
            .status(401)
            .json({ message: "Refresh token não fornecido." });
        }

        const { accessToken } = await authService.refreshToken(refreshToken);
        return res.status(200).json({ accessToken });
      } catch (error) {
        return res.status(401).json({
          message:
            error.message ||
            "Falha ao atualizar token. Por favor, faça login novamente.",
        });
      }
    },

    /**
     * @route POST /request-password-reset
     * Inicia o fluxo de redefinição de senha.
     */
    handleRequestPasswordReset: async (req, res) => {
      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).json({ message: "Email é obrigatório." });
        }
        await authService.requestPasswordReset(req.body);
        return res.status(204).send();
      } catch (error) {
        // Loga o erro, mas nunca falha para o usuário (previne enumeração)
        console.error("Erro em requestPasswordReset:", error);
        return res.status(204).send();
      }
    },

    /**
     * @route POST /reset-password
     * Conclui o fluxo de redefinição de senha.
     */
    handleResetPassword: async (req, res) => {
      try {
        const { token, novaSenha } = req.body;
        if (!token || !novaSenha) {
          return res
            .status(400)
            .json({ message: "Token e nova senha são obrigatórios." });
        }
        await authService.resetPassword(req.body);

        // Redireciona para a URL de sucesso
        return res.redirect(urls.passwordResetSuccess);
      } catch (error) {
        // Usa o handler de erro de redirecionamento
        return handleRedirectError(res, error, urls.passwordResetError);
      }
    },

    /**
     * @route POST /request-email-update
     * (Rota Protegida) Inicia a atualização do email do usuário logado.
     */
    handleRequestEmailUpdate: async (req, res) => {
      try {
        const { id: userId } = req.user;
        const { novoEmail, senhaAtual } = req.body;

        if (!novoEmail || !senhaAtual) {
          return res
            .status(400)
            .json({ message: "Novo email e senha atual são obrigatórios." });
        }

        await authService.requestEmailUpdate({ userId, novoEmail, senhaAtual });
        return res.status(204).send();
      } catch (error) {
        if (error.message.includes("Senha atual incorreta")) {
          return res.status(401).json({ message: error.message });
        }
        if (
          error.message.includes("email já está em uso") ||
          error.message.includes("seu email atual")
        ) {
          return res.status(400).json({ message: error.message });
        }
        return res.status(500).json({
          message: "Erro ao solicitar atualização de email.",
          error: error.message,
        });
      }
    },

    /**
     * @route GET /verify-email-update
     * Conclui o fluxo de atualização de email a partir de um token.
     */
    handleVerifyEmailUpdate: async (req, res) => {
      try {
        const { token } = req.query;
        await authService.verifyEmailUpdate(token);

        // Redireciona para a URL de sucesso
        return res.redirect(urls.emailUpdateSuccess);
      } catch (error) {
        // Usa o handler de erro de redirecionamento
        return handleRedirectError(res, error, urls.emailUpdateError);
      }
    },

    /**
     * @route PATCH /update-password
     * (Rota Protegida) Atualiza a senha do usuário logado.
     */
    handleUpdatePassword: async (req, res) => {
      try {
        const { id: userId } = req.user;
        const { senhaAntiga, novaSenha } = req.body;

        if (!senhaAntiga || !novaSenha) {
          return res
            .status(400)
            .json({ message: "Senha antiga e nova senha são obrigatórias." });
        }

        await authService.updatePassword({ userId, senhaAntiga, novaSenha });
        return res.status(204).send();
      } catch (error) {
        if (error.message.includes("Senha antiga está incorreta")) {
          return res.status(401).json({ message: error.message });
        }
        return res
          .status(500)
          .json({ message: "Erro ao atualizar senha.", error: error.message });
      }
    },
  };
}
