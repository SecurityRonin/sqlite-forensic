PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'Von塞巴斯蒂安erstellt' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO 'Von塞巴斯蒂安erstellt' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Christina', 'Vogel', '59423'),
	(20002, 'Karsten', 'Schröder', '64405'),
	(20003, 'Johanna', 'Jung', '35119'),
	(20004, 'Oliver', 'Vogt', '66271'),
	(20005, 'Elisabeth', 'Krause', '95326'),
	(20006, 'Silke', 'Vogt', '56630'),
	(20007, 'Stefan', 'Kühn', '24211'),
	(20008, 'Isabella', 'Friedrich', '21376'),
	(20009, 'Kai', 'Becker', '26906'),
	(20010, 'Clara', 'Schwarz', '95183');

