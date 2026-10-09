# Dashboard and Short-Link Plan

## Goal

After authentication, send users to a lightweight dashboard where they can create,
copy, view, and manage their own short links. Visiting a short code must redirect
to its saved destination URL.

## Current state

- Users are stored in PostgreSQL and receive a signed browser session after login
  or signup.
- The database already has a `links` table with `user_id`, `url`, and a unique
  `short_code`.
- Login and signup currently redirect to `/`; this needs to become `/dashboard`.

## Implementation steps

1. **Authentication helpers and route protection**
   - Add a router helper that validates the signed session cookie and exposes the
     current user ID to protected handlers.
   - Require a valid session for `/dashboard`, link creation, and link deletion.
   - Redirect unauthenticated visitors to `/login`.
   - Change successful login and signup redirects from `/` to `/dashboard`.

2. **Dashboard UI**
   - Create a dedicated, Tailwind-built `public/dashboard.html` using the same
     lightweight brutalist style as the auth screens.
   - Include a compact form for a destination URL and optional custom short code.
   - Show the current user’s newest links with destination, short URL, created
     date, and a one-click Copy button.
   - Include logout and an empty state.
   - Keep interaction dependency-free: use a small inline script for copying and
     submit the form with standard HTML.

3. **Create and list links**
   - Add `GET /dashboard` to render dashboard data for the signed-in user.
   - Add `POST /links` to validate a submitted `http`/`https` URL, generate a
     collision-resistant short code when one is not supplied, and insert the row
     with the current user ID.
   - Validate custom codes against the existing database rules and return useful
     form errors for invalid or already-used codes.
   - Generate the displayed short URL from the incoming request host so local
     development links work without hard-coded production domains.

4. **Short-link redirects**
   - Add `GET /:shortCode` after the explicit static/auth/dashboard routes.
   - Look up the saved destination URL by `short_code` and redirect with HTTP
     302/307.
   - Return a small 404 page when the code does not exist.
   - Ensure reserved route names (`login`, `signup`, `dashboard`, `links`, and
     `logout`) cannot be used as custom codes.

5. **Verification**
   - Add tests for session-protected routes, URL/custom-code validation, link
     ownership, and redirect behaviour.
   - Rebuild the purged Tailwind stylesheet with Bun.
   - Run `go test ./...` and manually verify signup → dashboard → create → copy
     → visit short URL → redirect.

## Route map

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/` | Landing page |
| `GET` | `/login` | Login form |
| `POST` | `/login` | Authenticate, then redirect to dashboard |
| `GET` | `/signup` | Signup form |
| `POST` | `/signup` | Create user, then redirect to dashboard |
| `POST` | `/logout` | Clear session |
| `GET` | `/dashboard` | User’s link dashboard |
| `POST` | `/links` | Create a short link |
| `GET` | `/:shortCode` | Redirect a saved short link |
