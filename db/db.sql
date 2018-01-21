CREATE TABLE `vulnerable_ips` (
    `id`         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `ip`         TEXT NOT NULL,
    `user`       TEXT NOT NULL,
    `pass`       TEXT NOT NULL,
    `created_at` DATE DEFAULT (datetime('now','localtime'))
);