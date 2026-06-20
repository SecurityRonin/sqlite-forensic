PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "(" (
    'id' INT UNSIGNED NOT NULL,
    'name' TEXT NOT NULL,
    'surname' TEXT NULL,
    'zip' INT UNSIGNED NULL
);

INSERT INTO "(" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Kerstin', 'Heinrich', '95689'),
	(20002, 'Rudolf', 'Vogt', '84094'),
	(20003, 'Elias', 'Weber', '34626'),
	(20004, 'Sascha', 'Thomas', '67731'),
	(20005, 'Christoph', 'Arnold', '67824'),
	(20006, 'Johannes', 'Klein', '86735'),
	(20007, 'Georg', 'Lehmann', '74193'),
	(20008, 'Theo', 'Seidel', '79312'),
	(20009, 'Michael', 'Wolf', '25878'),
	(20010, 'Lina', 'Günther', '56581');

