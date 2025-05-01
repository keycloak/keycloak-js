import express from 'express'
import path from 'node:path'
import { AUTH_SERVER_URL, CLIENT_ID } from '../support/common.ts'

// Set up Express
const app = express()

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

// Start server
app.listen(3000)
