# WhatsApp Validator

A self-hosted website and REST API that checks whether phone numbers are registered on WhatsApp and sends text messages. Each user links their own WhatsApp account by scanning a QR code, gets a personal API key, and every check or message made with that key goes through their own account.

> **Unofficial tool.** This project drives WhatsApp Web with [whatsapp-web.js](https://github.com/pedroslopez/whatsapp-web.js). It is not affiliated with or endorsed by WhatsApp or Meta, and automating WhatsApp is against WhatsApp's Terms of Service. Accounts that check or message many numbers can be **banned**. Use a spare number, keep the built-in limits, and only message people who expect to hear from you. For business messaging at scale, use the official [WhatsApp Business Platform](https://business.whatsapp.com/products/business-platform).

## Features

- **Accounts:** sign up with email and password; each user gets their own API key (show, copy, regenerate).
- **Your own WhatsApp:** link your account from the dashboard with a QR code; unlink at any time.
- **Check numbers on the website:** enter up to 20 numbers (row by row or pasted in bulk). Numbers on WhatsApp show a profile card with the photo, name, @username, About text and business details, when the person's privacy settings allow it.
- **Check an Excel file:** upload an `.xlsx` file with a `numbers` column (up to 1,000 rows) and download the results as a new `.xlsx` with a `whatsapp` column (Yes / No / Invalid number / Error).
- **REST API:** `POST /api/v1/check` (up to 50 numbers per request) and `POST /api/v1/send` (up to 20 numbers per request).
- **Account protection:** each account's requests are queued and spaced about 2.5 seconds apart; messages get an extra delay and a daily cap.

## Requirements

- [Node.js](https://nodejs.org/) **22.13 or newer** (24 recommended). The database uses Node's built-in `node:sqlite`.
- Google Chrome or Microsoft Edge installed. On Windows they are found automatically; elsewhere set `CHROME_PATH`.
- Roughly 200–300 MB of RAM for each linked WhatsApp account, since each one runs its own headless browser.

## Getting started

```bash
git clone https://github.com/MsCs235/WhatsApp_Validator.git
cd WhatsApp_Validator
npm install
npm start
```

Open http://localhost:3000, create an account, click **Link WhatsApp** and scan the QR code with your phone (WhatsApp → Settings → Linked devices → Link a device). Your API key is shown on the dashboard.

`example_input.xlsx` is a sample file for the Excel upload.

## API

Full documentation with curl, JavaScript, Python and PHP examples is served at `/docs.html` once the server is running.

Send your API key in the `X-API-Key` header (or `Authorization: Bearer <key>`).

### Check numbers

```http
POST /api/v1/check
X-API-Key: YOUR_API_KEY
Content-Type: application/json

{ "number": ["+201001234567", "+201000000000"] }
```

```json
{
  "total": 2,
  "summary": { "registered": 1, "not_registered": 1, "invalid": 0, "error": 0 },
  "results": [
    { "input": "+201001234567", "number": "+201001234567", "status": "registered", "whatsapp": true },
    { "input": "+201000000000", "number": "+201000000000", "status": "not_registered", "whatsapp": false }
  ]
}
```

### Send a message

```http
POST /api/v1/send
X-API-Key: YOUR_API_KEY
Content-Type: application/json

{ "number": ["+201001234567"], "message": "Hello!" }
```

Each number is checked first; numbers that aren't on WhatsApp are skipped without opening a chat. In both endpoints, `number` may also be a single string, in which case the response is a single result object.

Numbers must include the country code. `+201001234567`, `00201001234567` and `+20 100 123 4567` are all accepted.

## Configuration

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `CHROME_PATH` | auto-detected on Windows | Path to the Chrome or Edge executable |
| `MAX_ACTIVE_SESSIONS` | `10` | Maximum number of WhatsApp accounts linked at the same time |

Other limits (requests per minute, numbers per request, delay between requests, messages per day) are constants at the top of [`server.js`](server.js).

## Data and privacy

The server stores everything locally, and both locations are excluded from Git:

- `data.db`: SQLite database with user accounts (passwords are salted scrypt hashes), API keys, login sessions and a log of sent messages.
- `.wwebjs_auth/`: the saved WhatsApp Web login for each linked account.

Whoever runs the server can technically access every WhatsApp account linked to it. Only let people link accounts if they trust the operator, and keep the machine secure.

## Project structure

```
server.js          Express server: accounts, WhatsApp sessions, website endpoints and the REST API
public/index.html  Login page and dashboard
public/docs.html   API documentation
example_input.xlsx Sample file for the Excel upload
```
