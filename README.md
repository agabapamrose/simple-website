# Simple Website

Express + EJS + MySQL app with:
- Home page (`/home`)
- Task manager (`/tasks`)
- Users and roles manager (`/users-roles`)
- Individual team accounts (`/individual-accounts`)
- Public registration (`/register`)
- Token-based password reset (`/reset-password`)
- Team-leader task assignment with member dropdown + email notifications
- Centralized role-based access control (RBAC)
- CSRF protection for authenticated `POST` requests
- In-memory rate limiting and secure response headers

## Setup

1. Install dependencies:
   `npm install`
2. Copy env template:
   `copy .env.example .env`
3. Start server:
   `npm start`

## Roles Matrix

- `Admin`
  - Developer workspace role
  - Can manage users and roles
  - Cannot create/edit/complete/delete tasks
  - Cannot manage teams from the app UI
- `Editor`
  - Can view tasks
  - Can create/edit/complete/delete tasks
  - Cannot manage users and roles
- `Team Leader`
  - Can view tasks
  - Can create/edit/complete/delete tasks
  - Can assign tasks to members in their own team
  - Can access teams in read-only mode when assigned to a team
  - Cannot manage users, roles, or teams
- `Viewer`
  - Can view tasks only
  - Cannot create/edit/delete tasks
  - Cannot manage users, roles, or teams

## Route Access

- `GET /tasks`: `Editor`, `Team Leader`, `Viewer` (and personal users via account type scope)
- `POST /add`, `GET /edit/:id`, `POST /update/:id`, `POST /delete/:id`, `POST /complete/:id`: `Editor`, `Team Leader` (and personal users via account type scope)
- `GET /teams`: assigned team users only
- `GET /individual-accounts`, `POST /teams/users/add`: `Admin` only
- `POST /teams/members/*`: `Team Leader` only
- `POST /teams/add`, `POST /teams/toggle/:id`: disabled in this workspace
- `GET /users-roles`, `POST /roles/*`, `POST /users/*`: `Admin` only

## Account Login Notes

- Login accepts either `username` or `email` plus password.
- Accounts created from Admin management pages use default password `123`.
- Users can change their password later from `Reset Password`.

## Email Notifications

- Task assignment emails are sent when a Team Leader assigns or reassigns a team task.
- Configure SMTP in `.env`:
  `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_SECURE`
- If SMTP is not configured, assignments still save and the server logs a skipped-email message.

## Testing

- Run authorization tests:
  `npm test`

Server runs on `http://localhost:4000` by default.

## Deploy To Firebase Hosting (Spark Plan)

This repository is configured for Spark-friendly static deployment.

- Public files are served from `public/`
- No Cloud Functions are deployed
- Dynamic backend features (Express routes, MySQL, auth/task APIs) are not available in Spark mode

1. Install dependencies:
   `npm install`
2. Log into Firebase CLI:
   `npx firebase login`
3. Confirm the Firebase project alias in `.firebaserc` (currently: `mood-a3611`).
4. Deploy static hosting:
   `npm run firebase:deploy`

Useful local preview command:
- `npm run firebase:serve`

## Deploy Full Backend (Render + MySQL)

Use this path if you want login/tasks/database features publicly available.

Files prepared:
- `render.yaml` (Render blueprint)
- `.env.backend.example` (backend environment template)

1. Push this repository to GitHub.
2. Create a hosted MySQL database (any provider with public connection details).
3. In Render, create a new Blueprint service from this repo (it reads `render.yaml`).
4. Set environment variables from `.env.backend.example`:
   - `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
   - `APP_BASE_URL` set to your Render URL (for example `https://simple-website-backend.onrender.com`)
   - `DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`, `DEFAULT_ADMIN_USERNAME`
   - Optional: `SMTP_*`
5. Deploy in Render.
6. Open your Render URL and test:
   - `/login`
   - `/home`
   - `/tasks`

Notes:
- Keep Firebase Spark deployment for static pages if you want, but your dynamic app runs from the Render URL.
- Render free tier may sleep after inactivity.
