# StudyDeck — full-stack flashcards

## Features
- Real server-side registration/login
- Passwords hashed with bcrypt
- HTTP-only login cookie
- User-specific decks and progress
- CSV upload from the website
- Delete decks
- Correct/incorrect toggle
- Progress synced to the server
- Clean responsive UI

## Run locally
```bash
npm install
# Linux/macOS:
JWT_SECRET="replace-with-a-long-random-secret" npm start
# Windows PowerShell:
$env:JWT_SECRET="replace-with-a-long-random-secret"; npm start
```
Open http://localhost:3000

## Important
This app stores data in `data.json`. Use persistent disk/storage when deploying. Do NOT use the default JWT secret in production.

GitHub Pages can host the frontend but cannot run this Node.js backend. Deploy the whole project to a Node-capable host (or use a managed database/auth service) for real server login.
