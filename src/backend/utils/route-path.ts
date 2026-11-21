/**
 * The form Express matches a path in. Express routes ignore case and accept
 * one trailing slash, so `/users/Change-Password/` reaches the same handler
 * as `/users/change-password`. Any path check that refuses or limits by a
 * case-sensitive, anchored regex must test this form, or the variant walks
 * past it.
 */
export function canonicalRoutePath(path: string): string {
  const cut = path.search(/[?#]/);
  const bare = cut >= 0 ? path.slice(0, cut) : path;
  return bare.toLowerCase().replace(/\/+$/, "") || "/";
}
