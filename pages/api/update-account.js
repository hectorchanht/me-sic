import { gql } from 'graphql-request';
import { getSession } from 'next-auth/react';

import { hygraphClient } from '../../lib/hygraph';

const UpdateNextUser = gql`
  mutation UpdateNextUser($userId: ID!, $name: String, $bio: String) {
    user: updateNextUser(
      data: { name: $name, bio: $bio }
      where: { id: $userId }
    ) {
      id
      name
      email
      bio
    }
  }
`;

export default async (req, res) => {
  const session = await getSession({ req });

  if (session) {
    const { name, bio } = JSON.parse(req.body);

    const { user } = await hygraphClient.request(UpdateNextUser, {
      userId: session.userId,
      name,
      bio,
    });

    res.json(user);
  } else {
    res.send({
      error: 'You must be sign in to update your account.',
    });
  }
};