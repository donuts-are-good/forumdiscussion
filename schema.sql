CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discussions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_email TEXT NOT NULL,
	title TEXT NOT NULL,
	body TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS replies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	discussion_id INTEGER NOT NULL,
	parent_id INTEGER,
	user_email TEXT NOT NULL,
	body TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (discussion_id) REFERENCES discussions (id) ON DELETE CASCADE,
	FOREIGN KEY (parent_id) REFERENCES replies (id) ON DELETE CASCADE,
	FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS roles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	is_admin BOOLEAN NOT NULL DEFAULT 0,
	is_banned BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_roles (
	user_id INTEGER NOT NULL,
	role_id INTEGER NOT NULL,
	PRIMARY KEY (user_id, role_id),
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cookies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	selector CHAR(12) UNIQUE NOT NULL,
	validator CHAR(64) NOT NULL,
	user_email TEXT NOT NULL,
	expires TIMESTAMP NOT NULL,
	FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
);
