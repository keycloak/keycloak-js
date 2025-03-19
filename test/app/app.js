import express from 'express'
import path from 'node:path'

// Set up Express
const app = express()

// Expose 'public' directory and Keycloak JS source.
app.use(express.static(path.resolve(import.meta.dirname, 'public')))
app.use(express.static(path.resolve(import.meta.dirname, '../../lib')))

// Start server
app.listen(3000)
