import {HttpProblems, ZuploContext, ZuploRequest} from "@zuplo/runtime";

export default async function policy(
  request: ZuploRequest,
  context: ZuploContext,
  options: never,
  policyName: string
) {
 
  const allowedOrigin = request.user.data.origin;

  if (request.headers.get("origin") !== allowedOrigin) {
    return HttpProblems.forbidden(request, context, { detail: "Invalid Auth Profile" });
  }

  return request;
}
