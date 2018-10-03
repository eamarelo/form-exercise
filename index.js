const http = require('https')
const fs = require("fs")
const express = require('express')
const helmet = require('helmet')
const bodyParser = require('body-parser')
const escape_html = require('escape-html')
const session = require('express-session')
const crypto = require('crypto')
const bcrypt = require('bcrypt');
const csrf = require('csurf')
const cookieParser = require('cookie-parser')
const redisStore = require('connect-redis')(session)

const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || 10)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex')

const storage = {
  messages: [],
  users: []
}

const app = express()
const options = {
  key: fs.readFileSync(process.env.SSL_KEY),
  cert: fs.readFileSync(process.env.SSL_CERT)
};

const isPasswordValid = function (password) {
  if (password !== undefined && password.length > 5 && password.length < 125) {
    return true
  }
  return false
}

const homePage = function ({ username, csrfToken }) {
  const loginForm = `
    <h1>signin</h1>
    <form method="post" action="/login">
      <input type="hidden" name="_csrf" value="${csrfToken}"/>
      <label>username:</label>
      <input name="username" type="text"/>
      <label>password:</label>
      <input name="password" type="password"/>
      <button>login</submit>
    </form>
  `

  const signupForm = `
    <h1>signup</h1>
    <form method="post" action="/signup">
      <input type="hidden" name="_csrf" value="${csrfToken}"/>
      <label>username:</label>
      <input name="username" type="text"/>
      <label>password:</label>
      <input name="password" type="password"/>
      <label>password confirmation:</label>
      <input name="check_password" type="password"/>
      <button>signup</submit>
    </form>
  `

  const logoutForm = `
    <form method="post" action="/logout">
      <input type="hidden" name="_csrf" value="${csrfToken}"/>
      <button>logout</submit>
    </form>
  `
  const messageList = function() {
    return storage.messages.map(x => `<li><b>${x.username}:</b> ${x.message}</li>`).join('')
  }

  const newMessageForm = `
    <form method="post" action="/messages">
      <input type="hidden" name="_csrf" value="${csrfToken}"/>
      <label>message:</label>
      <input name="message" type="text"/>
      <button>send</submit>
    </form>
  `

  return `
    <!doctype html>
    <html lang="fr">
    <head>
      <meta charset="utf-8">
      <title>Demo App</title>
    </head>
      <body>
        <h1>HTML page over TLS</h1>
          <div>
            ${ username === undefined ? loginForm : logoutForm }
          </div>
          <div>
            ${ username === undefined ? signupForm : ""}
          </div>
        <h1>Messages</h1>
        <div>
          <ul>
            ${ messageList() }
          </ul>
        </div>
        <div>
          ${ username === undefined ? "" : newMessageForm }
        </div>
      </body>
    </head>
  `
}

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    imgSrc: ['*'],
    upgradeInsecureRequests: true
  }
}))
app.use(helmet.frameguard({ action: 'deny' }))
app.use(helmet.noSniff())
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))
app.use(helmet.ieNoOpen())
app.use(helmet.referrerPolicy({ policy: 'no-referrer' }))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(csrf({ cookie: true }))
app.use(session({
 store: new redisStore({ host: 'localhost', port: 6379}),
  name: 'SSID',
  secret: SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: { secure: true, httpOnly: true, domain: 'localhost', path: '/' }
}))

app.get('/', function (req, res) {
  const currentUser = req.session.currentUser || {}
  res.send(homePage({ username: currentUser.username, csrfToken: req.csrfToken()}))
})

app.post('/signup', function (req, res) {
  const result = storage
    .users
    .filter(x => x.username === req.body.username)

  if (result.length === 1) {
    res.send('already exist user')
    return
  }

  if (req.body.username === undefined) {
    res.send('bad username')
    return
  }

  const username = escape_html(req.body.username)
  if (req.body.username !== username) {
    res.send('bad username')
    return
  }

  if (req.body.username.length < 3 || req.body.username.length > 125) {
    res.send('bad username')
    return
  }

  if (!isPasswordValid(req.body.password)) {
    res.send('invalid password')
    return
  }

  if (req.body.password !== req.body.check_password) {
    res.send('invalid password')
    return
  }

  const user = {
    username: username,
    passwordHash: bcrypt.hashSync(req.body.password, saltRounds)
  }

  storage.users.push(user)

  req.session.currentUser = user
  res.redirect('/')
})

app.post('/login', function (req, res) {
  const result = storage
    .users
    .filter(x => x.username === req.body.username)

  if (!isPasswordValid(req.body.password)) {
    res.send('invalid creds')
    return
  }

  if (result.length == 1) {
    if (bcrypt.compareSync(req.body.password || "", result[0].passwordHash)) {
      req.session.currentUser = result[0]
      res.redirect('/')
      return
    }
  }
  res.send('invalid creds')
})

app.post('/logout', function (req, res) {
  req.session.destroy()
  res.redirect('/')
})

app.post('/messages', function (req, res) {
  if (req.session.currentUser === undefined) {
    res.send('invalid creds')
    return
  }

  const escape_msg = escape_html(req.body.message || "")
  if (escape_msg.length < 255 && escape_msg.length > 1) {
    storage.messages.push({
      message: escape_msg,
      username: req.session.currentUser.username
    })
    res.redirect('/')
  } else {
    res.send('invalid message')
  }
})

http.createServer(options, app).listen(process.env.PORT);