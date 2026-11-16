# MEZOX MUSIC (Server)

Node/Express + Socket.IO + SQLite backend (auth, friends/invites, listen-together relay, song lyrics).

## Setup
```bash
cp .env.example .env   # set JWT_SECRET, BASE_URL, OAuth creds as needed
npm install
npm start              # PORT defaults to 3000
```

## Key endpoints
- `POST /auth/register` `{username, displayName, age, password}`
- `POST /auth/login` `{username, password}`
- `POST /auth/oauth` `{provider, idToken/accessToken, email, displayName}`
- `GET /auth/discord/start|callback`, `GET /auth/telegram/start|callback`
- `GET /friends`, `GET /friends/invites`, `POST /friends/invite`, `POST /friends/accept`
- `POST /friends/listen/join` `{friendUsername}` → `{roomId}`
- `POST /lyrics` `{title, artist, trackId}` → `{lyrics}` (fetched from lyrics sources, no AI key required)
- Socket.IO: `join_room`, `leave_room`, `play_sync`, `invite_received`, `friends_updated`

## Notes
- Host behind HTTPS for production/OAuth/deep-links. `mezox.db` stores users/friends/invites (back it up).
- Lyrics endpoint fetches from public lyrics sources (e.g. LRCLIB/lyrics.ovh) matched to the track; availability depends on those sources. Use your own OAuth credentials and operate within service quotas/terms.
