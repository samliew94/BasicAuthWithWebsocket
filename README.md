# Notes:   
1) Client is a frontend framework (I'm using Svelte 3 deployed at port 5173) AND PostMan.
2) Server only accepts username "sam" and password "liew" as the sole credential.
3) There's no need to implement UserDetails or UserDetailsService because of 2).
4) To test Websocket with PostMan, kvps "COOKIE" and "SESSION=XXXXXXXX" must be provided at request header.
5) The value of SESSION can be obtained by inspecting Response Header cookie section after login
6) If using Spring Session, the session ids returned are e.g "01c64083-caca-4e39-a851-5e2b8fca2a5b". Spring websocket DOES NOT recognize this session id. It should look like "MDFjNjQwODMtY2FjYS00ZTM5LWE4NTEtNWUyYjhmY2EyYTVi".
7) If testing using Websocket from browser, directly connecting to websocket endpoint ("websocket") should work automatically whilst preserving the authentication.
