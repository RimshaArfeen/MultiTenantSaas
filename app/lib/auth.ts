// lib/auth.ts
import { NextAuthOptions, getServerSession } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { prisma } from "./prisma";
import bcrypt from "bcryptjs";

declare module "next-auth" {
  interface User {
    role?: string;
    companyId?: string | null;
    hasCompany?: boolean;
  }

  interface Session {
    user: {
      id: string;
      email: string;
      name: string;
      role: string;
      companyId: string | null;
      hasCompany: boolean;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id?: string;
    role?: string;
    companyId?: string | null;
    hasCompany?: boolean;
  }
}

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Invalid credentials");
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
          include: { company: true },
        });

        if (!user || !user.password) {
          throw new Error("Invalid credentials");
        }

        const isPasswordValid = await bcrypt.compare(
          credentials.password,
          user.password
        );

        if (!isPasswordValid) {
          throw new Error("Invalid credentials");
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name || user.email,
          role: user.role || "MEMBER",
          companyId: user.companyId ?? null,
          hasCompany: !!user.companyId,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger }) {
      // First sign-in: copy fields from the user object
      if (user) {
        token.id = user.id;
        token.role = user.role || "MEMBER";
        token.companyId = user.companyId ?? null;
        token.hasCompany = !!user.companyId;
      }

      // Refresh from DB on session update(), or if the user has no company yet
      // (e.g. new Google user who has just completed company setup)
      if (token.id && (trigger === "update" || !token.companyId)) {
        const dbUser = await prisma.user.findUnique({
          where: { id: token.id },
          select: { companyId: true, role: true },
        });

        token.companyId = dbUser?.companyId ?? null;
        token.hasCompany = !!dbUser?.companyId;
        if (dbUser) token.role = dbUser.role;
      }

      return token;
    },

    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
        session.user.companyId = (token.companyId as string | null) ?? null;
        session.user.hasCompany = !!token.hasCompany;
      }
      return session;
    },
  },
  pages: {
    signIn: "/auth",
    error: "/auth",
    signOut: "/auth",
  },
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60,
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: process.env.NODE_ENV === "development", // prints adapter errors in the terminal
};

export async function getAuthSession() {
  return await getServerSession(authOptions);
}