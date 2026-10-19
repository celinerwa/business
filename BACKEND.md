# Backend and deployment

The site and API run on Node.js 18+ and use MongoDB Atlas for durable storage. The Render blueprint is in `render.yaml`; the team admin page is served at `/admin.html`.

## Run locally

1. Install Node.js 18 or newer.
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.
3. Run `npm install`, then `npm start`. The server loads `.env` automatically for local development; variables set by Render or your shell take precedence.
4. Open `http://localhost:3000` for the site and `http://localhost:3000/admin.html` for the admin page.

Render injects configured environment values automatically. URL-encode special characters in the MongoDB username or password when building the Atlas connection string.

## MongoDB Atlas and Render

Create an Atlas cluster and database user, allow network connections from Render (or use Atlas's broad IP access option if your plan has no static outbound IPs), then copy the Atlas connection string. Do not commit real credentials.

Deploy this repository as a Render Web Service using `render.yaml`, or configure manually:

- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/api/health`
- Required environment variables: `MONGODB_URI`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`
- Optional environment variable: `MONGODB_DATABASE` (defaults to `business_management`)
- Optional local setting: `MONGODB_DNS_SERVERS` (comma-separated DNS resolvers, only needed when the local DNS provider blocks Atlas SRV lookups)

On startup, the server creates required indexes and bootstraps the administrator from the environment. Use a unique admin email and a strong password of at least 10 characters. The configured admin account is created or updated on every startup. Customer signup cannot grant admin access.

## API

All API request and response bodies use JSON. Validation errors include a `fields` object. Authenticated routes use `Authorization: Bearer <token>`; session tokens expire after seven days and are stored hashed in MongoDB.

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| GET | `/api/health` | Public | Health and MongoDB connection check |
| POST | `/api/auth/signup` | Public | Create customer account with `{ name, email, password }` |
| POST | `/api/auth/signin` | Public | Sign in with `{ email, password }` |
| POST | `/api/auth/signout` | Token | Revoke session |
| GET | `/api/auth/me` | Token | Current user and role |
| GET/POST | `/api/admin/team` | Team | List team accounts or create a staff login |
| POST | `/api/contact` | Public | Store a contact enquiry (requires `privacy: true`) |
| POST | `/api/requests` | Customer | Submit a management request |
| GET | `/api/requests` | Customer | List their requests |
| GET | `/api/requests/:id` | Customer | Read their request |
| GET | `/api/admin/overview` | Team | Dashboard counts |
| GET | `/api/admin/requests` | Team | List and filter management requests |
| PATCH | `/api/admin/requests/:id` | Team | Update status and internal notes |
| GET/POST | `/api/admin/businesses` | Team | List or create managed business records |
| PATCH | `/api/admin/businesses/:id` | Team | Update business status and details |
| GET | `/api/admin/contacts` | Team | List contact messages |
| PATCH | `/api/admin/contacts/:id` | Team | Update contact follow-up status |

The signup/signin, contact, and management request forms are connected to the API. The request page sends file names only; file contents are not uploaded. The admin page supports request review, private team notes, business onboarding/tracking, contact follow-up, and staff logins. Team members can work the queues; only the environment-configured account has administrator role, and staff creation cannot grant that role. Creating a business from a request links the records and prevents a second linked business record. The customer request confirmation/dashboard page remains a static demo page.

Uploaded files are not accepted or stored; management requests may contain only up to ten uploaded file names as metadata. Passwords are hashed with scrypt, and session tokens are hashed before storage. Admin and staff accounts currently have broad access to customer submissions and business records; finer-grained permissions and change history can be added in a later phase.
