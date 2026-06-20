PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
      'id' INTEGER,
      'name' TEXT,
      'surname' TEXT,
      'zip' INTEGER,
      CONSTRAINT constName PRIMARY KEY (id) UNIQUE(name));

INSERT INTO 'users' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Sven', 'Keller', '65604'),
	(20002, 'Martha', 'Krause', '24226'),
	(20003, 'Fabian', 'Krämer', '84432'),
	(20004, 'Heinrich', 'Martin', '12355'),
	(20005, 'Lisa', 'Huber', '29593'),
	(20006, 'Katharina', 'Fischer', '50677'),
	(20007, 'Mike', 'Thomas', '92708'),
	(20008, 'Martina', 'Kühn', '94513'),
	(20009, 'Ben', 'Kuhn', '46535'),
	(20010, 'Victoria', 'Möller', '74420');

