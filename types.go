package main

import (
	"time"
)

type User struct {
	ID       int         `db:"id" json:"-"`
	RoleIDs  []int       `json:"-"`
	Email    string      `db:"email" json:"email,omitempty"`
	Password string      `db:"password" json:"password,omitempty"`
	Profile  ProfileData `json:"profile"`
}

type ProfileData struct {
	Username      string `db:"username" json:"username"`
	Discriminator int    `db:"discriminator" json:"discriminator"`
	Avatar        string `db:"avatar" json:"avatar,omitempty"`
}

type Role struct {
	ID       int    `db:"id" json:"id,omitempty"`
	Name     string `db:"name" json:"name,omitempty"`
	IsAdmin  bool   `db:"is_admin" json:"is_admin,omitempty"`
	IsBanned bool   `db:"is_banned" json:"is_banned,omitempty"`
}

type Discussion struct {
	ID          int       `db:"id" json:"id,omitempty"`
	Title       string    `db:"title" json:"title,omitempty"`
	Body        string    `db:"body" json:"body,omitempty"`
	Owner       User      `json:"owner,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at,omitempty"`
	Replies     []*Reply  `json:"replies,omitempty"`
	NumReplies  int       `json:"num_replies"`
	LatestReply time.Time `json:"latest_reply"`
}

type Reply struct {
	ID           int       `db:"id" json:"id,omitempty"`
	DiscussionID int       `db:"discussion_id" json:"discussion_id,omitempty"`
	ParentID     *int      `db:"parent_id" json:"parent_id,omitempty"`
	Owner        User      `json:"owner,omitempty"`
	Body         string    `db:"body" json:"body,omitempty"`
	CreatedAt    time.Time `db:"created_at" json:"created_at,omitempty"`
	Children     []*Reply  `json:"children,omitempty"`
}
