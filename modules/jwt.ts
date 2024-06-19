import { ZuploContext, ZuploRequest, environment, HttpProblems } from "@zuplo/runtime";
import { SignJWT } from "jose"

export default async function (request: ZuploRequest, context: ZuploContext) {

  const origin = request.headers.get("origin");

  if (!origin) {
    return HttpProblems.forbidden(request, context, { detail: "Invalid Auth Profile"});
  }

  const userTagId = crypto.randomUUID();
  const consumerName = `consumer-${crypto.randomUUID()}`;
  const sub = `user-${crypto.randomUUID()}`;

  const secret = new TextEncoder().encode(
    environment.JWT_SECRET,
  )
  const alg = 'HS256'

  const jwt = await new SignJWT({ userTagId, sub, origin })
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .sign(secret)

  return { token: jwt }
}