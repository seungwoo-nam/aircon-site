// 홈페이지 파일(public)은 그대로 보여주고, /api/ 요청만 서버 기능으로 보냅니다.
import { onRequest } from "./api.js";
export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname.startsWith("/api/")) return onRequest({ request, env });
    return env.ASSETS.fetch(request);
  },
};
