package main

import (
	"database/sql"
	"log"
)

func getDB() *sql.DB {
	db, err := sql.Open("sqlite3", "sqlite.db")
	if err != nil {
		log.Fatal(err)
	}
	return db
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
	err := db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", email).Scan(&user.ID, &user.Email, &user.Password)
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

func GetDiscussionByID(db *sql.DB, id string) (Discussion, error) {
	var discussion Discussion
	err := db.QueryRow("SELECT id, user_email, title, body, created_at FROM discussions WHERE id = ?", id).Scan(&discussion.ID, &discussion.Owner.Email, &discussion.Title, &discussion.Body, &discussion.CreatedAt)
	if err != nil {
		return Discussion{}, err
	}
	return discussion, nil
}

func GetAllDiscussions(db *sql.DB) ([]Discussion, error) {
	rows, err := db.Query("SELECT id, user_email, title, body, created_at FROM discussions")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var discussions []Discussion
	for rows.Next() {
		var discussion Discussion
		if err := rows.Scan(&discussion.ID, &discussion.Owner.Email, &discussion.Title, &discussion.Body, &discussion.CreatedAt); err != nil {
			return nil, err
		}
		discussions = append(discussions, discussion)
	}
	return discussions, nil
}