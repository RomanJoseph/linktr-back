import { connection } from '../db/db.js';

async function findUsers(word) {
	return connection.query(
		'SELECT id, name, image FROM users WHERE name ILIKE $1',
		[`%${word}%`]
	);
}

async function findUserById(id) {
	return connection.query('SELECT * FROM users WHERE id = $1', [Number(id)]);
}

async function listUserPosts(id){
	return connection.query(
		`
		SELECT 
			posts.*, users.name, users.image 
		FROM posts
		RIGHT JOIN users 
			ON posts."userId" = users.id
		WHERE users.id = $1
		ORDER BY posts."id" DESC 
		LIMIT 20`,
		[Number(id)]
	);
}

export { findUsers, findUserById, listUserPosts };