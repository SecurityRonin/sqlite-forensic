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

CREATE TABLE members (
	'mid' INT UNSIGNED NOT NULL,
	'mname' TEXT NOT NULL,
	'msurname' TEXT NULL,
	'mcodeA' INT NULL,
	'mcodeB' FLOAT NULL
);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(50001, 'Isabella', 'Seidel', -405753613, 3077447306.40084),
	(50002, 'Mila', 'Walter', -951465551, 2396459811.08605),
	(50003, 'Andrea', 'Fischer', -211130379, -3035596859.65795),
	(50004, 'Matthias', 'Jung', 378090189, 157017984.96629),
	(50005, 'Richard', 'Ludwig', 24336938, -253979738.45432),
	(50006, 'Emilia', 'Schulze', -265683969, 430735342.87081),
	(50007, 'Tanja', 'Fuchs', -580212572, -4180799680.38052),
	(50008, 'Elfriede', 'Koch', 826785739, -2501046027.75585),
	(50009, 'Michaela', 'Sauer', -391470339, 929024967.33192),
	(50010, 'Luis', 'Herrmann', 1201670164, 3517549381.83238);

INSERT INTO members 
	(mid, mname, msurname, mcodeA, mcodeB)
	VALUES
	(20001, 'Jonas', 'Fuchs', -941960468, 299926696.01921),
	(20002, 'Pia', 'Albrecht', -429903287, 3043058075.96215),
	(20003, 'Rudolf', 'Krüger', 1689432059, -4512579315.11504),
	(20004, 'Annika', 'Koch', 768413509, 4721312890.63083),
	(20005, 'Martin', 'Schumacher', 1181659012, -1312896309.56617),
	(20006, 'Emelie', 'Schäfer', 1106348597, -4866072246.74247),
	(20007, 'Katja', 'Möller', -1375522997, -1619283988.42890),
	(20008, 'Michaela', 'Schmid', 675052841, -3392035755.51139),
	(20009, 'Daniel', 'Vogt', 959749089, -4279739935.54699),
	(20010, 'Marco', 'Groß', 843397883, -2359841539.22640);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DROP TABLE users;
DROP TABLE members;
