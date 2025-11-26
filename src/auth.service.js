import crypto from "crypto";
import { AuthTokenType } from "@prisma/client";

/**
 * Gera um token criptograficamente seguro para tokens de uso único (email, reset).
 * @returns {string} Um token hexadecimal de 64 caracteres.
 */
function generateSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Cria a fábrica de serviços de autenticação.
 * @param {object} dependencies - As dependências injetadas.
 * @param {PrismaClient} dependencies.prismaClient - A instância do Prisma.
 * @param {object} dependencies.helpers - Os helpers de hashing e token.
 * @param {object} dependencies.emailService - O serviço de envio de email.
 * @param {any} dependencies.defaultUserRole - O cargo padrão para novos usuários.
 * @param {function} dependencies.onUserRegistered - O hook de pós-registro.
 * @returns {object} O objeto de serviço de autenticação.
 */
export function createAuthService({
  prismaClient,
  helpers,
  emailService,
  defaultUserRole,
  onUserRegistered,
}) {
  // --- FUNÇÕES INTERNAS DE TOKEN DE USO ÚNICO (Verificação/Reset) ---

  /**
   * Cria um token de uso único, armazena seu hash e envia o token puro por email.
   * @param {string} usuarioId - O ID do usuário.
   * @param {AuthTokenType} tipo - 'EMAIL_VERIFICATION', 'PASSWORD_RESET', 'EMAIL_UPDATE'.
   * @param {function} sendFunction - A função de email a ser chamada (ex: emailService.sendVerificationEmail).
   * @param {string} emailDestino - O email para onde enviar o token.
   * @param {object} [payload=null] - Dados extras para armazenar no token (ex: { novoEmail: '...' }).
   * @param {PrismaClient} [tx=prismaClient] - O cliente Prisma (pode ser uma transação).
   */
  const createAndSendToken = async (
    usuarioId,
    tipo,
    sendFunction,
    emailDestino,
    payload = null,
    tx = prismaClient
  ) => {
    // 1. Gera o token puro (para o email)
    const tokenPuro = generateSecureToken();
    // 2. Cria o hash (para o banco)
    const tokenHash = helpers.hashToken(tokenPuro);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60); // 1 hora

    // 3. Armazena o HASH no banco
    await tx.authToken.create({
      data: {
        token: tokenHash, // Armazena o HASH
        tipo,
        expiresAt,
        usuarioId,
        payload: payload || undefined, // Armazena o payload se existir
      },
    });

    // 4. Envia o token PURO por email
    await sendFunction(emailDestino, tokenPuro);
  };

  /**
   * (Interno) Valida um token de uso único (puro), o marca como usado e RETORNA O REGISTRO DO TOKEN.
   * @param {string} tokenPuro - O token vindo da URL/body.
   * @param {AuthTokenType} tipo - O tipo de token esperado.
   * @param {object} [tx=prismaClient] - O cliente Prisma (pode ser uma transação).
   * @returns {Promise<AuthToken>} O registro do AuthToken encontrado e marcado como usado.
   */
  const validateAndUseToken = async (tokenPuro, tipo, tx = prismaClient) => {
    if (!tokenPuro) {
      throw new Error("Token não fornecido.");
    }
    const tokenHash = helpers.hashToken(tokenPuro);

    // 1. Busca pelo HASH
    const authToken = await tx.authToken.findFirst({
      where: {
        token: tokenHash,
        tipo,
        usado: false,
        expiresAt: { gt: new Date() },
      },
    });

    if (!authToken) {
      throw new Error("Token inválido, expirado ou já utilizado.");
    }

    // 2. Marca o token como usado e o retorna
    const authTokenUsado = await tx.authToken.update({
      where: { id: authToken.id },
      data: { usado: true },
    });

    return authTokenUsado;
  };

  /**
   * (Interno) Invalida TODOS os refresh tokens de um usuário.
   * Usado após mudança de senha ou email para forçar o logout de todos os dispositivos.
   */
  const _invalidateAllRefreshTokens = async (usuarioId, tx = prismaClient) => {
    await tx.authRefreshToken.updateMany({
      where: { usuarioId, revogado: false },
      data: { revogado: true },
    });
  };

  // --- FUNÇÕES PÚBLICAS DO SERVIÇO ---

  return {
    /**
     * Registra um novo usuário, chama a função pós-registro (via hook) e envia o email de verificação.
     */
    async register({ nome, email, senha, ...extras }) {
      const userExists = await prismaClient.usuario.findUnique({
        where: { email },
      });

      let novoUsuario;
      const senhaHash = await helpers.hashPassword(senha);

      if (userExists) {
        // CENÁRIO A: Usuário existe e JÁ ESTÁ verificado
        if (userExists.emailVerified) {
          throw new Error("Email já cadastrado.");
        }

        // CENÁRIO B: Usuário existe mas NÃO ESTÁ verificado
        extras.userExists = true;
        novoUsuario = await prismaClient.$transaction(async (tx) => {
          // 1. Atualiza o usuário
          const usuario = await tx.usuario.update({
            where: {
              id: userExists.id,
            },
            data: {
              nome,
              senha: senhaHash,
              emailVerificado: false,
            },
          });

          // 2. Chama o hook customizado do app (ex: para criar RelatorioUsuario)
          if (onUserRegistered) {
            await onUserRegistered(tx, usuario, extras);
          }

          // 3. Envia email de verificação
          await createAndSendToken(
            usuario.id,
            AuthTokenType.EMAIL_VERIFICATION,
            emailService.sendVerificationEmail,
            usuario.email,
            null, // Sem payload
            tx
          );

          return usuario;
        });
      } else {
        novoUsuario = await prismaClient.$transaction(async (tx) => {
          // 1. Cria o usuário
          const usuario = await tx.usuario.create({
            data: {
              nome,
              email,
              senha: senhaHash,
              cargo: defaultUserRole,
              emailVerificado: false,
            },
          });

          // 2. Chama o hook customizado do app (ex: para criar RelatorioUsuario)
          if (onUserRegistered) {
            await onUserRegistered(tx, usuario, extras);
          }

          // 3. Envia email de verificação
          await createAndSendToken(
            usuario.id,
            AuthTokenType.EMAIL_VERIFICATION,
            emailService.sendVerificationEmail,
            usuario.email,
            null, // Sem payload
            tx
          );

          return usuario;
        });
      }

      const { senha: _, ...usuarioSemSenha } = novoUsuario;
      return usuarioSemSenha;
    },

    /**
     * Verifica um token de email, marca o usuário como verificado.
     */
    async verifyEmail(tokenPuro) {
      const authToken = await validateAndUseToken(
        tokenPuro,
        AuthTokenType.EMAIL_VERIFICATION
      );

      const usuario = await prismaClient.usuario.update({
        where: { id: authToken.usuarioId },
        data: { emailVerificado: true },
      });

      return usuario;
    },

    /**
     * Autentica um usuário, verifica se o email foi verificado e retorna Access/Refresh tokens.
     */
    async login({ email, senha }) {
      const usuario = await prismaClient.usuario.findUnique({
        where: { email },
      });
      if (!usuario) throw new Error("Credenciais inválidas.");
      if (!usuario.emailVerificado)
        throw new Error("Por favor, verifique seu email antes de fazer login.");

      const senhaValida = await helpers.comparePassword(senha, usuario.senha);
      if (!senhaValida) throw new Error("Credenciais inválidas.");

      const accessToken = helpers.generateAccessToken(usuario);
      const {
        selector,
        validatorHash,
        tokenPuro: refreshToken,
      } = helpers.generateRefreshToken(usuario.id);

      // Armazena o refresh token no DB (com o padrão Selector/Validator)
      await prismaClient.authRefreshToken.create({
        data: {
          selector,
          validatorHash, // Armazena o hash do validador
          usuarioId: usuario.id,
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7), // 7 dias
        },
      });

      return { accessToken, refreshToken };
    },

    /**
     * Invalida um Refresh Token (Logout).
     */
    async logout(refreshTokenPuro) {
      if (!refreshTokenPuro) return;
      const [selector, validator] = refreshTokenPuro.split(":");
      if (!selector || !validator) return;

      const tokenRecord = await prismaClient.authRefreshToken.findUnique({
        where: { selector },
      });
      if (!tokenRecord) return; // Token não existe, não faz nada

      // VERIFICAÇÃO DE SEGURANÇA (Timing Attack Safe):
      // Compara o hash do validator recebido com o hash armazenado.
      const validatorHash = helpers.hashToken(validator);
      const isValid = crypto.timingSafeEqual(
        Buffer.from(validatorHash),
        Buffer.from(tokenRecord.validatorHash)
      );

      if (isValid) {
        await prismaClient.authRefreshToken.update({
          where: { id: tokenRecord.id },
          data: { revogado: true }, // Marca como revogado
        });
      }
      // Se não for válido, não fazemos nada (alguém pode estar tentando adivinhar tokens).
    },

    /**
     * Emite um novo Access Token usando um Refresh Token válido.
     */
    async refreshToken(refreshTokenPuro) {
      const [selector, validator] = refreshTokenPuro.split(":");
      if (!selector || !validator) throw new Error("Refresh Token malformado.");

      const tokenRecord = await prismaClient.authRefreshToken.findUnique({
        where: { selector },
      });

      // 1. Verifica se o token existe, não foi revogado e não expirou
      if (!tokenRecord || tokenRecord.revogado)
        throw new Error("Refresh Token inválido ou revogado.");
      if (tokenRecord.expiresAt < new Date())
        throw new Error("Refresh Token expirado.");

      // 2. Compara o validator (seguro contra timing attacks)
      const validatorHash = helpers.hashToken(validator);
      const isValid = crypto.timingSafeEqual(
        Buffer.from(validatorHash),
        Buffer.from(tokenRecord.validatorHash)
      );

      if (!isValid) throw new Error("Refresh Token inválido.");

      // 3. Sucesso! Emite um novo Access Token
      const usuario = await prismaClient.usuario.findUnique({
        where: { id: tokenRecord.usuarioId },
      });
      if (!usuario)
        throw new Error("Usuário associado ao token não encontrado.");

      const accessToken = helpers.generateAccessToken(usuario);
      return { accessToken };
    },

    /**
     * Inicia o fluxo de redefinição de senha.
     */
    async requestPasswordReset({ email }) {
      const usuario = await prismaClient.usuario.findUnique({
        where: { email },
      });

      // Sempre retorne sucesso, mesmo se o email não existir (previne enumeração de usuários)
      if (usuario) {
        await createAndSendToken(
          usuario.id,
          AuthTokenType.PASSWORD_RESET,
          emailService.sendPasswordResetEmail,
          usuario.email
        );
      }
    },

    /**
     * Conclui o fluxo de redefinição de senha.
     */
    async resetPassword({ token, novaSenha }) {
      // 1. Valida o token e pega o ID do usuário
      const authToken = await validateAndUseToken(
        token,
        AuthTokenType.PASSWORD_RESET
      );
      const { usuarioId } = authToken;

      // 2. Hasha a nova senha
      const novaSenhaHash = await helpers.hashPassword(novaSenha);

      // 3. ATUALIZAÇÃO DE SEGURANÇA: Invalida todas as sessões ativas
      await prismaClient.$transaction(async (tx) => {
        await tx.usuario.update({
          where: { id: usuarioId },
          data: { senha: novaSenhaHash },
        });
        // Invalida todos os refresh tokens
        await _invalidateAllRefreshTokens(usuarioId, tx);
      });
    },

    /**
     * Inicia o fluxo de atualização de email (para usuário logado).
     * Exige a senha atual para segurança.
     */
    async requestEmailUpdate({ userId, novoEmail, senhaAtual }) {
      // 1. VERIFICAR A SENHA ATUAL PRIMEIRO
      const usuario = await prismaClient.usuario.findUnique({
        where: { id: userId },
      });
      if (!usuario) {
        throw new Error("Usuário não encontrado.");
      }

      const senhaValida = await helpers.comparePassword(
        senhaAtual,
        usuario.senha
      );
      if (!senhaValida) {
        throw new Error("Senha atual incorreta."); // Re-autenticação falhou
      }

      // 2. Verifica se o novo email é válido
      if (usuario.email === novoEmail) {
        throw new Error("Este já é o seu email atual.");
      }
      const emailExists = await prismaClient.usuario.findUnique({
        where: { email: novoEmail },
      });
      if (emailExists) {
        throw new Error("Este email já está em uso por outra conta.");
      }

      // 3. Envia token de verificação para o NOVO email
      await createAndSendToken(
        usuario.id,
        AuthTokenType.EMAIL_UPDATE,
        emailService.sendUpdateEmailConfirmation,
        novoEmail,
        { novoEmail } // Armazena o email no payload do token
      );
    },

    /**
     * Conclui o fluxo de atualização de email.
     */
    async verifyEmailUpdate(tokenPuro) {
      // 1. Valida o token
      const authToken = await validateAndUseToken(
        tokenPuro,
        AuthTokenType.EMAIL_UPDATE
      );

      // 2. Pega o novo email e o ID do usuário do token
      const { novoEmail } = authToken.payload;
      const { usuarioId } = authToken;

      if (!novoEmail || !usuarioId) {
        throw new Error(
          "Token de atualização de email inválido (sem payload ou ID de usuário)."
        );
      }

      // 3. Verifica (de novo) se o email foi pego por alguém
      const emailExists = await prismaClient.usuario.findUnique({
        where: { email: novoEmail },
      });
      if (emailExists && emailExists.id !== usuarioId) {
        throw new Error(
          "Este email foi registrado por outra conta. Por favor, tente novamente."
        );
      }

      // 4. ATUALIZAÇÃO DE SEGURANÇA: Invalida sessões
      await prismaClient.$transaction(async (tx) => {
        await tx.usuario.update({
          where: { id: usuarioId },
          data: { email: novoEmail },
        });
        // Como o email (login) mudou, invalida todos os tokens
        await _invalidateAllRefreshTokens(usuarioId, tx);
      });
    },

    /**
     * Atualiza a senha do usuário (para usuário logado).
     */
    async updatePassword({ userId, senhaAntiga, novaSenha }) {
      const usuario = await prismaClient.usuario.findUnique({
        where: { id: userId },
      });
      if (!usuario) throw new Error("Usuário não encontrado.");

      const senhaValida = await helpers.comparePassword(
        senhaAntiga,
        usuario.senha
      );
      if (!senhaValida) throw new Error("Senha antiga está incorreta.");

      const novaSenhaHash = await helpers.hashPassword(novaSenha);

      // 3. ATUALIZAÇÃO DE SEGURANÇA: Invalida sessões
      await prismaClient.$transaction(async (tx) => {
        await tx.usuario.update({
          where: { id: userId },
          data: { senha: novaSenhaHash },
        });
        // Invalida todos os refresh tokens
        await _invalidateAllRefreshTokens(userId, tx);
      });
    },
  };
}
