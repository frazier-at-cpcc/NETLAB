# Browser RDP MVP

This prototype uses `guacamole-lite` and `guacd` to bridge a browser to one
RDP target. RDP credentials are held by the Node process and placed only in an
encrypted Guacamole token. The prototype access token is intentionally
temporary; production must replace it with a one-time session token issued by
lab-api.

Run locally:

```sh
npm ci
HTTP_PORT=8090 WS_PORT=8091 WS_PUBLIC_URL=ws://127.0.0.1:8091/ \
  PROTOTYPE_ACCESS_TOKEN=demo-token \
  GUACAMOLE_TOKEN_KEY=01234567890123456789012345678901 \
  RDP_HOST=10.10.10.42 RDP_USERNAME=student RDP_PASSWORD='secret' \
  GUACD_HOST=127.0.0.1 npm start
```

Start `guacd` separately, then open `http://127.0.0.1:8090/?access=demo-token`.
The browser receives only the encrypted token and never receives the RDP
password or target credentials.
