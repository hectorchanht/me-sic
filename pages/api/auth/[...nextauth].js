import { compare, hash } from 'bcrypt';
import { gql } from 'graphql-request';
import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import GoogleProvider from "next-auth/providers/google";

import { hygraphClient } from '../../../lib/hygraph';

const GetUserByEmail = gql`
  query GetUserByEmail($email: String!) {
    user: nextUser(where: { email: $email }, stage: DRAFT) {
      id
      password
    }
  }
`;

const CreateNextUserByEmail = gql`
  mutation CreateNextUserByEmail($email: String!, $password: String, $image: String, $name: String) {
    newUser: createNextUser(data: { email: $email, password: $password, image: $image, name: $name }) {
      id
    }
  }
`;

export default NextAuth({
  secret: process.env.NEXTAUTH_SECRET,
  jwt: {
    secret: process.env.NEXTAUTH_SECRET,
  },
  session: {
    strategy: 'jwt',
  },
  // debug: process.env.NODE_ENV === 'development',
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    CredentialsProvider({
      name: 'Email and Password',
      credentials: {
        email: {
          label: 'Email',
          type: 'email',
          placeholder: 'hi@there.com',
        },
        password: {
          label: 'Password',
          type: 'password',
          placeholder: 'Password',
        },
      },
      authorize: async ({ email, password }) => {
        const { user } = await hygraphClient.request(GetUserByEmail, {
          email,
        });

        if (!user) {
          const { newUser } = await hygraphClient.request(
            CreateNextUserByEmail,
            {
              email,
              password: await hash(password, 12),
            }
          );

          return {
            id: newUser.id,
            username: email,
            email,
          };
        }

        const isValid = await compare(password, user.password);

        if (!isValid) {
          throw new Error('Wrong credentials. Try again.');
        }

        return {
          id: user.id,
          username: email,
          email,
        };
      },
    }),
  ],
  callbacks: {
    async signIn({ account, profile }) {
      if (account.provider === "google") {
        const { user } = await hygraphClient.request(GetUserByEmail, {
          email: profile?.email,
        });
        if (!user) {
          await hygraphClient.request(
            CreateNextUserByEmail,
            {
              email: profile?.email,
              image: profile?.picture,
              name: profile?.name
            }
          );
        }

        // return profile.email_verified && profile.email.endsWith("@example.com")
      }
      return true // Do different verification for other providers that don't have `email_verified`
    },
    async session({ session, token }) {

      session.userId = token.sub;

      if (token?.picture) { // replace userId for google users
        const { user } = await hygraphClient.request(GetUserByEmail, {
          email: token?.email,
        });
        session.userId = user.id;
      }
      return Promise.resolve(session);
    },
  },
});