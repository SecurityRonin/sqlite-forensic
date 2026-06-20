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
	(20001, 'Sabine', 'Schulze', 385172865, -4731774022.67781),
	(20002, 'Mats', 'Schumacher', 104515788, -885357985.21962),
	(20003, 'Meike', 'Schubert', -264182854, -3481406447.70181),
	(20004, 'Gertrud', 'Vogel', 1028238665, 4465122567.24067),
	(20005, 'Karsten', 'Beck', -433465140, 4719536835.19714),
	(20006, 'Alexandra', 'Brandt', 1207262815, 4033715710.52527),
	(20007, 'Meike', 'Baumann', 990064014, -1393943702.05418),
	(20008, 'Maximilian', 'Wagner', -1048186912, 2762732048.40847),
	(20009, 'Lia', 'Kaiser', -169836736, 36160566.39522),
	(20010, 'Mathilda', 'Walter', 445414094, 4139278898.54614);

INSERT INTO users 
	(id, name, surname, codeA, codeB)
	VALUES
	(20011, 'Markus', 'Schubert', -2114982565, 406129376.68624),
	(20012, 'Hanna', 'Roth', -769808978, -3974051782.38361),
	(20013, 'Tobias', 'Kühn', 36228416, 903737501.19644),
	(20014, 'Melanie', 'Frank', 1099691035, -385153985.29598),
	(20015, 'Daniela', 'Roth', 41052167, -2256388984.27430),
	(20016, 'Nele', 'Becker', -718594726, 2050259796.46028),
	(20017, 'Elli', 'Kraus', 540659627, -1071491919.49120),
	(20018, 'Willi', 'Martin', -1236270983, -164065749.92652),
	(20019, 'Christoph', 'Möller', 1601938748, 878729268.85203),
	(20020, 'Laura', 'Wagner', 1489225832, 4098043082.79326);

