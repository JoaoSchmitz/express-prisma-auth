import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// Gera um token aleatório seguro (para emails, selectors, etc.)
const generateSecureToken = (bytes = 32) => {
  return crypto.randomBytes(bytes).toString("hex");
};

// Hash rápido para tokens (SHA-256)
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

export function createAuthHelpers({
  jwtSecret,
  jwtExpiresIn,
}) {
  return {
    hashPassword: async (password) => {
      const saltRounds = 10;
      return bcrypt.hash(password, saltRounds);
    },

    comparePassword: async (password, hash) => {
      return bcrypt.compare(password, hash);
    },

    hashToken,

    generateAccessToken: (usuario) => {
      const payload = {
        id: usuario.id,
        email: usuario.email,
        cargo: usuario.cargo,
      };
      return jwt.sign(payload, jwtSecret, { expiresIn: jwtExpiresIn });
    },

    generateRefreshToken: () => {
      // Padrão Selector/Validator
      const selector = generateSecureToken(16);
      const validator = generateSecureToken(32);

      const tokenPuro = `${selector}:${validator}`; // Para enviar ao cliente
      const validatorHash = hashToken(validator); // Para salvar no DB

      return { selector, validatorHash, tokenPuro };
    },

    verifyAccessToken: (token) => {
      try {
        return jwt.verify(token, jwtSecret);
      } catch (error) {
        return null; // Token inválido ou expirado
      }
    },
    
    generateEmailToken: () => {
      return generateSecureToken(32);
    },
  };
}
