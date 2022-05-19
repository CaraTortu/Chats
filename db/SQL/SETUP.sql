/*
    Created by: Javier Díaz on 19/04/22.
    https://github.com/CaraTortu/Chats
*/

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  email TEXT,
  password TEXT,
  twofa_secret TEXT,
  twofa_image TEXT,
  twofa_scanned INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  verify_token TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  owner INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER,
  user INTEGER,
  message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER
);