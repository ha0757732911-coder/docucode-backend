# DocuCode Backend API

Cloudflare Worker backend for DocuCode AI documentation generator.

## Live API URL
https://docucode-api.ha0757732911.workers.dev

## Tech Stack
- Cloudflare Workers (serverless backend)
- Cloudflare D1 (SQLite database)
- Google Gemini AI API
- JWT authentication (no external libraries)

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Register new user |
| POST | /api/auth/login | Login user |
| POST | /api/document | Generate documentation |
| GET | /api/history | Get user history |
| DELETE | /api/history/:id | Delete history item |
| GET | /api/admin/users | Get all users (admin only) |

## Features
- Password hashing with PBKDF2
- JWT authentication
- AI-powered Python documentation generation
- User history tracking
- Admin panel
