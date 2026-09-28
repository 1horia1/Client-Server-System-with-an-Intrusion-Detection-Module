import sqlite3
from db import DB_PATH

def migrate_audit_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 1. Redenumim tabelul vechi
        cursor.execute("ALTER TABLE audit_logs RENAME TO audit_logs_old")
        
        # 2. Creăm noul tabel cu user_id NULL și coloana created_at
        # Această structură respectă cerințele de la pagina 7 a proiectului 
        cursor.execute("""
            CREATE TABLE audit_logs(
                id TEXT PRIMARY KEY NOT NULL,
                user_id TEXT NULL, 
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NULL,
                message TEXT NULL,
                ip_address TEXT NULL,
                user_agent TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # 3. Copiem datele (Mapăm coloanele vechi la cele noi)
        # Observă că am pus coloanele conform schemei tale anterioare
        cursor.execute("""
            INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, message, ip_address, user_agent)
            SELECT id, user_id, action, RESOURCE_TYPE, resource_id, message, IP_address, USER_AGENT
            FROM audit_logs_old
        """)
        
        # 4. Ștergem tabelul vechi
        cursor.execute("DROP TABLE audit_logs_old")
        
        conn.commit()
        print("Migrare finalizată cu succes! Datele au fost păstrate.")
        
    except Exception as e:
        conn.rollback()
        print(f"Eroare la migrare: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_audit_table()