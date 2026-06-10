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
	(20001, 'Martin', 'Arnold', -417174382, -843767763.97404),
	(20002, 'Rudolf', 'Stein', 1097111674, -1823422176.21553),
	(20003, 'Philipp', 'Walter', -1350359784, 3995479917.61727),
	(20004, 'Alina', 'Bauer', -161218587, -4336345214.08768),
	(20005, 'Mika', 'Berger', -575016498, 1916520482.35597),
	(20006, 'Anni', 'Schulte', 792423694, 2157257966.30478),
	(20007, 'Elsa', 'Friedrich', -139574232, 4688036418.37465),
	(20008, 'Daniela', 'Roth', -349880615, 4591159727.23400),
	(20009, 'Clara', 'Schuster', 872039535, 2491499892.19918),
	(20010, 'Nico', 'Lorenz', 1398371778, 4182440223.72292);

PRAGMA secure_delete=0;
PRAGMA secure_delete;

DELETE FROM users where id == 20001;
DELETE FROM users where id == 20004;
DELETE FROM users where id == 20008;
DELETE FROM users where id == 20006;
DELETE FROM users where id == 20010;

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20010, 'Willi', 'Brandt', 193398469, 1836062575.14845),
	(20011, 'Andrea', 'Berger', -541590667, -3739680330.61348),
	(20012, 'Bianca', 'Seidel', 115013121, -3341639870.00549),
	(20013, 'Werner', 'Schäfer', 1515276056, -355795293.74642),
	(20014, 'Florian', 'Schmitz', 904231242, 2016027018.90097),
	(20015, 'Johannes', 'Kaiser', 621919309, -4069854602.71586),
	(20016, 'Fabian', 'Böhm', -391192117, -3825573585.38060),
	(20017, 'Silke', 'Kraus', 67584945, 4409725609.89192),
	(20018, 'Gustav', 'Heinrich', -249770504, 2665587080.48686),
	(20019, 'Tanja', 'Thomas', -449796169, 3569325310.44321);

