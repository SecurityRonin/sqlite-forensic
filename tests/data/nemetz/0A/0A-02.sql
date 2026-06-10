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
	(20001, 'Hanna', 'Haas', -379052688, -4180108615.74677),
	(20002, 'Anne', 'Krüger', 994868910, -1026449709.21169),
	(20003, 'Hans', 'Winkler', 831601473, 2904244669.66849),
	(20004, 'Christina', 'Kühn', -1073926705, -798950738.17994),
	(20005, 'Gertrud', 'Martin', 604028607, 942711940.00855),
	(20006, 'Christine', 'Haas', -1062862954, -4829990425.99927),
	(20007, 'Mathilda', 'Friedrich', -1541011779, 1372355723.92696),
	(20008, 'Hans', 'Bauer', -459286706, 105753208.09416),
	(20009, 'Julius', 'Pfeiffer', 926593357, 2802150313.65033),
	(20010, 'Fabian', 'Fischer', -526407351, 3749719680.63606),
	(20011, 'Markus', 'Schulze', 710281185, 4035145514.19539),
	(20012, 'Wilhelm', 'Fuchs', -473771406, -4531736001.15428),
	(20013, 'Daniel', 'Bauer', -361726213, 4866881528.80728),
	(20014, 'Sascha', 'Scholz', -1965508740, 4944252977.12174),
	(20015, 'Laura', 'König', -809181854, -894413141.48456),
	(20016, 'Isabell', 'Haas', -104790992, 1964242503.49600),
	(20017, 'Jonathan', 'Heinrich', -759817358, -1839089638.94429),
	(20018, 'Irma', 'Schwarz', 898461, -3415825915.71651),
	(20019, 'Leonie', 'Sauer', -1262750550, -4613941293.03002),
	(20020, 'Elfriede', 'Roth', 1237600051, 535602334.67054);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 20001;
DELETE FROM users where id == 20009;
DELETE FROM users where id == 20005;
DELETE FROM users where id == 20004;
DELETE FROM users where id == 20002;
DELETE FROM users where id == 20003;
DELETE FROM users where id == 20006;
DELETE FROM users where id == 20008;
DELETE FROM users where id == 20010;
DELETE FROM users where id == 20007;
DELETE FROM users where id == 20011;
DELETE FROM users where id == 20019;
DELETE FROM users where id == 20015;
DELETE FROM users where id == 20014;
DELETE FROM users where id == 20012;
DELETE FROM users where id == 20013;
DELETE FROM users where id == 20016;
DELETE FROM users where id == 20018;
DELETE FROM users where id == 20020;
DELETE FROM users where id == 20017;

DROP TABLE users;
