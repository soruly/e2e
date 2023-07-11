# e2e

Self-hosted End-to-End Encryption in plain JS with zero dependency

[![License](https://img.shields.io/github/license/soruly/e2e.svg?style=flat-square)](https://github.com/soruly/e2e/blob/master/LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/soruly/e2e/node.js.yml?style=flat-square)](https://github.com/soruly/e2e/actions)

## Getting Started

Prerequisites: nodejs >= 16

```
git clone https://github.com/soruly/e2e.git
cd e2e
npm install
node server.js
```

Note: In order for PWA to work, you must host the server behind a reverse proxy (like nginx) with HTTPS

### Environment Variables

- Copy `.env.example` to `.env`
- Edit `.env` as you need

```
SERVER_PORT=3000        # (optional) Default: 3000
SERVER_ADDR=127.0.0.1   # (optional) Default: 127.0.0.1
```

### Run by pm2

You also can use [pm2](https://pm2.keymetrics.io/) to run this in background.

Use below commands to start / restart / stop server.

```
npm run start
npm run stop
npm run reload
npm run restart
npm run delete
```
