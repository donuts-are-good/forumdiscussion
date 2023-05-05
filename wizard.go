package main

import "database/sql"

func IsSetupCompleted(db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM config WHERE key = 'setup_completed' AND value = '1'").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
