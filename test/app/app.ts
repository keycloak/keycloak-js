import express from 'express'
import path from 'node:path'
import { AUTH_SERVER_URL, CLIENT_ID, REDIRECT_SERVICE_URL } from '../support/common.ts'

const app = express()

// Expose middleware to simulate a 'redirect service' between the application and auth server.
app.use((req, res, next) => {
  if (req.hostname === REDIRECT_SERVICE_URL.hostname) {
    const { origin } = req.query

    if (typeof origin !== 'string') {
      res.status(400).send('Missing origin query parameter')
      return
    }

    const redirectUrl = new URL(req.originalUrl, origin)
    redirectUrl.searchParams.delete('origin')
    res.redirect(redirectUrl.toString())
    return
  }
  next()
})

// Expose 'public' directory and Keycloak JS source.
app.use(express.static(path.resolve(import.meta.dirname, 'public')))
app.use(express.static(path.resolve(import.meta.dirname, '../../lib')))

// Expose an endpoint to serve the Keycloak adapter configuration.
app.get('/adapter-config.json', (req, res) => {
  const { realm } = req.query

  if (typeof realm !== 'string') {
    res.status(400).json({ error: 'Missing realm parameter.' })
    return
  }

  res.json({
    'auth-server-url': AUTH_SERVER_URL.toString(),
    realm,
    resource: CLIENT_ID
  })
})

app.listen(3000)
