package main

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

func ensureTablesPresent(db *sqlx.DB) error {
	tableCreationStatements := []string{
		`CREATE TABLE IF NOT EXISTS config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT UNIQUE NOT NULL,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			username TEXT,
			avatar TEXT,
			discriminator INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS discussions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS replies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			discussion_id INTEGER NOT NULL,
			parent_id INTEGER,
			user_email TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (discussion_id) REFERENCES discussions (id) ON DELETE CASCADE,
			FOREIGN KEY (parent_id) REFERENCES replies (id) ON DELETE CASCADE,
			FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			is_admin BOOLEAN NOT NULL DEFAULT 0,
			is_banned BOOLEAN NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS user_roles (
			user_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, role_id),
			FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS cookies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			selector CHAR(12) UNIQUE NOT NULL,
			validator CHAR(64) NOT NULL,
			user_email TEXT NOT NULL,
			expires TIMESTAMP NOT NULL,
			FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
		);`,
	}

	for _, stmt := range tableCreationStatements {
		_, err := db.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (u *User) GetRoles(db *sql.DB) ([]Role, error) {
	roles := []Role{}
	for _, roleID := range u.RoleIDs {
		role, err := GetRoleByID(db, roleID)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func GetRoleByID(db *sql.DB, roleID int) (Role, error) {
	var role Role
	err := db.QueryRow("SELECT id, name, is_admin, is_banned FROM roles WHERE id = ?", roleID).Scan(&role.ID, &role.Name, &role.IsAdmin, &role.IsBanned)
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

func GetUserByEmail(db *sql.DB, email string) (User, error) {
	var user User
	err := db.QueryRow("SELECT * FROM users WHERE email = ?", email).Scan(&user.ID, &user.Email, &user.Password, &user.Profile.Username, &user.Profile.Discriminator, &user.Profile.Avatar)
	if err != nil {
		return User{}, err
	}

	roleIDs, err := GetUserRoleIDs(db, user.ID)
	if err != nil {
		return User{}, err
	}
	user.RoleIDs = roleIDs

	return user, nil
}

func GetUserRoleIDs(db *sql.DB, userID int) ([]int, error) {
	rows, err := db.Query("SELECT role_id FROM user_roles WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roleIDs []int
	for rows.Next() {
		var roleID int
		if err := rows.Scan(&roleID); err != nil {
			return nil, err
		}
		roleIDs = append(roleIDs, roleID)
	}

	return roleIDs, nil
}
func GetAllDiscussions(db *sql.DB) ([]Discussion, error) {
	rows, err := db.Query(`SELECT d.id, u.username, u.discriminator, u.avatar, d.title, d.body, d.created_at,
                                  COUNT(r.id) as num_replies, COALESCE(MAX(r.created_at), d.created_at) as latest_reply
                           FROM discussions d
                           INNER JOIN users u ON d.user_id = u.id
                           LEFT JOIN replies r ON r.discussion_id = d.id
                           GROUP BY d.id, u.username, u.discriminator, u.avatar, d.title, d.body, d.created_at
                           ORDER BY latest_reply DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var discussions []Discussion
	for rows.Next() {
		var discussion Discussion
		var latestReplyStr string
		if err := rows.Scan(&discussion.ID, &discussion.Owner.Profile.Username, &discussion.Owner.Profile.Discriminator, &discussion.Owner.Profile.Avatar, &discussion.Title, &discussion.Body, &discussion.CreatedAt, &discussion.NumReplies, &latestReplyStr); err != nil {
			return nil, err
		}

		discussion.LatestReply, err = time.Parse("2006-01-02 15:04:05", latestReplyStr)
		if err != nil {
			return nil, err
		}

		discussions = append(discussions, discussion)
	}

	return discussions, nil
}

func GetRepliesByDiscussionID(db *sql.DB, discussionID string) ([]*Reply, error) {
	rows, err := db.Query(`SELECT r.id, r.discussion_id, r.parent_id, u.email, u.username, u.discriminator, u.avatar, r.body, r.created_at FROM replies r INNER JOIN users u ON r.user_email = u.email WHERE r.discussion_id = ?`, discussionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	replies := []*Reply{}
	for rows.Next() {
		var reply Reply
		err := rows.Scan(&reply.ID, &reply.DiscussionID, &reply.ParentID, &reply.Owner.Email, &reply.Owner.Profile.Username, &reply.Owner.Profile.Discriminator, &reply.Owner.Profile.Avatar, &reply.Body, &reply.CreatedAt)
		if err != nil {
			return nil, err
		}
		replies = append(replies, &reply)
	}
	return replies, nil
}

func GetDiscussionByID(db *sql.DB, id string) (Discussion, error) {
	var discussion Discussion
	err := db.QueryRow(`SELECT d.id, u.email, u.username, u.discriminator, u.avatar, d.title, d.body, d.created_at FROM discussions d INNER JOIN users u ON d.user_id = u.id WHERE d.id = ?`, id).Scan(&discussion.ID, &discussion.Owner.Email, &discussion.Owner.Profile.Username, &discussion.Owner.Profile.Discriminator, &discussion.Owner.Profile.Avatar, &discussion.Title, &discussion.Body, &discussion.CreatedAt)
	if err != nil {
		return Discussion{}, err
	}
	return discussion, nil
}

func GetReplyByID(db *sql.DB, id string) (Reply, error) {
	var reply Reply
	err := db.QueryRow("SELECT id, discussion_id, user_email, body, created_at FROM replies WHERE id = ?", id).Scan(&reply.ID, &reply.DiscussionID, &reply.Owner.Email, &reply.Body, &reply.CreatedAt)
	if err != nil {
		return Reply{}, err
	}
	return reply, nil
}
