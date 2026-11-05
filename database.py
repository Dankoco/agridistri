import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'agridistri.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table des stocks (Intrants)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            type TEXT NOT NULL,
            quantite REAL NOT NULL,
            unite TEXT NOT NULL
        )
    ''')

    # Table des agriculteurs (Bénéficiaires)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agriculteurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            region TEXT,
            contact TEXT UNIQUE,
            numero_identite TEXT,
            type_piece TEXT,
            photo_identite_url TEXT
        )
    ''')

    # Table des distributeurs (Staff)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS distributeurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nom TEXT NOT NULL,
            region TEXT,
            role TEXT DEFAULT 'distributeur'
        )
    ''')

    # Table des demandes (Soumises par les agriculteurs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS demandes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agriculteur_id INTEGER,
            stock_id INTEGER,
            quantite REAL NOT NULL,
            statut TEXT DEFAULT 'EN_ATTENTE',
            distributeur_id INTEGER,
            date_demande DATETIME DEFAULT CURRENT_TIMESTAMP,
            date_validation DATETIME,
            contact_notification TEXT,
            FOREIGN KEY (agriculteur_id) REFERENCES agriculteurs (id),
            FOREIGN KEY (stock_id) REFERENCES stocks (id),
            FOREIGN KEY (distributeur_id) REFERENCES distributeurs (id)
        )
    ''')

    # Inventaire par distributeur
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS distributeur_stocks (
            distributeur_id INTEGER NOT NULL,
            stock_id INTEGER NOT NULL,
            quantite REAL NOT NULL DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (distributeur_id, stock_id),
            FOREIGN KEY (distributeur_id) REFERENCES distributeurs (id),
            FOREIGN KEY (stock_id) REFERENCES stocks (id)
        )
    ''')

    # Table des distributions (Historique - Validées par le staff)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS distributions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agriculteur_id INTEGER,
            stock_id INTEGER,
            quantite REAL NOT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agriculteur_id) REFERENCES agriculteurs (id),
            FOREIGN KEY (stock_id) REFERENCES stocks (id)
        )
    ''')

    # Table des transactions de stock (ajouts / retraits)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            distributeur_id INTEGER,
            stock_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            quantite REAL NOT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (distributeur_id) REFERENCES distributeurs (id),
            FOREIGN KEY (stock_id) REFERENCES stocks (id)
        )
    ''')

    # Table des journaux d'audit (sécurité — qui a fait quoi, quand et depuis quelle IP)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            detail TEXT,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'SUCCESS',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Initialiser les données de base
    cursor.execute("SELECT COUNT(*) FROM stocks")
    if cursor.fetchone()[0] == 0:
        stocks = [
            ("Semence de Maïs", "Semence", 500, "kg"),
            ("Engrais NPK", "Engrais", 1200, "kg"),
            ("Urée", "Engrais", 800, "kg"),
            ("Pesticide Bio", "Aide", 150, "L")
        ]
        cursor.executemany("INSERT INTO stocks (nom, type, quantite, unite) VALUES (?, ?, ?, ?)", stocks)

    cursor.execute("SELECT COUNT(*) FROM distributeurs")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO distributeurs (username, password, nom, region, role) VALUES (?, ?, ?, ?, ?)",
            (
                "admin",
                "scrypt:32768:8:1$RdUJDJnpwYSv9jcf$8e4fbfdb23a26e78761bb7cf0f01d07701f090d93e665d1bd9904e853cb85c8e6ad3e447a331f8a5e54c44203d8161586c0aa0729b89931c9124a10382096dcf",
                "Administrateur Général",
                "National",
                "admin"
            )
        )
        cursor.execute(
            "INSERT INTO distributeurs (username, password, nom, region, role) VALUES (?, ?, ?, ?, ?)",
            (
                "distributeur1",
                "scrypt:32768:8:1$N7At1vzgWrkJTlDK$dd315e48ed16e67a8ca6246e7be4f3f7dcf963d3343b511fe83a5add6ff8ada7e873cc7bca1aa14cbac291fcb3fb2ef7bcc86927f5a47798f362a4e3244ac4df",
                "Distributeur Région Ouest",
                "Ouest",
                "distributeur"
            )
        )
        cursor.execute(
            "INSERT INTO distributeurs (username, password, nom, region, role) VALUES (?, ?, ?, ?, ?)",
            (
                "distributeur2",
                "scrypt:32768:8:1$C7hSKrEz4thrg5uh$d3ead7014734fbe75e05d22891de744a636109391a18d7e499ce42b1e65fdaf1766cb88e43e7dc9beafe172cc4fe3ee803cc5a616ea0a2c9b3a9f9ba4e5cb60d",
                "Distributeur Région Est",
                "Est",
                "distributeur"
            )
        )

    cursor.execute('''
        INSERT INTO distributeur_stocks (distributeur_id, stock_id, quantite)
        SELECT d.id, s.id, s.quantite
        FROM distributeurs d
        JOIN stocks s ON 1 = 1
        WHERE d.role = 'distributeur'
          AND NOT EXISTS (
              SELECT 1
              FROM distributeur_stocks ds
              WHERE ds.distributeur_id = d.id
                AND ds.stock_id = s.id
          )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Base de données initialisée avec succès.")
