PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE users (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'codeA' INT NULL,
	'codeB' FLOAT NULL
);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20001, 'Silvia', 'Walter', 57780645, 1814964072.22700),
	(20002, 'Karsten', 'Jung', -953549484, 3283453270.92495),
	(20003, 'August', 'Groß', -152555078, 1457847094.37650),
	(20004, 'Lea', 'Keller', -1603066786, 935726410.67939),
	(20005, 'Walter', 'Vogel', -1696742655, 33751043.97244),
	(20006, 'Oliver', 'Koch', 118953440, -3754540732.48177),
	(20007, 'Jakob', 'Dietrich', -555876883, 4998077480.12155),
	(20008, 'Melina', 'Schulz', 402896619, 1315141108.96510),
	(20009, 'Daniela', 'Günther', -151098348, -4530710484.61400),
	(20010, 'Katharina', 'Kuhn', -554724609, -1521867288.51957);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DROP TABLE users;

CREATE TABLE members (
	'mid' INT UNSIGNED NOT NULL,
	'mname' TEXT NOT NULL,
	'msurname' TEXT NULL,
	'mcodeA' INT NULL,
	'mcodeB' FLOAT NULL
);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20001, 'Victoria', 'Stein', -266682679, 1276456749.19545),
	(20002, 'Jannik', 'Engel', 1218946828, -420162596.46982),
	(20003, 'Mats', 'Berger', -722327944, 4296834640.80879),
	(20004, 'Alfred', 'Lang', 273427164, 2920103509.87320),
	(20005, 'Martina', 'Lehmann', -640110447, -4810664504.67830);

